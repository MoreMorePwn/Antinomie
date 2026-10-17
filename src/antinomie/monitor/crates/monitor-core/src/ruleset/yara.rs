// SPDX-License-Identifier: MIT
//! YARA source lexing for the rule index.
use super::*;

pub(super) fn parse_yara(text: &str) -> Vec<IndexedRule> {
    yara_blocks(text)
        .into_iter()
        .map(|(name, body, helper)| IndexedRule {
            id: name.clone(),
            name,
            file: String::new(),
            helper,
            tags: Vec::new(),
            severity: String::new(),
            license: Some(meta_in(&body, "license"))
                .filter(|license| !license.is_empty())
                .unwrap_or_else(|| meta_in(&body, REPOSITORY_LICENSE_META)),
            source_url: meta_in(&body, "source_url"),
            condition: clip(&meta_in(&body, "description"), 180),
            references: reference_list(&body),
            evidence: vec!["sample".into(), "memory".into(), "recovered-file".into()],
            compatible: true,
            reason: String::new(),
            content_sha256: format!("{:x}", Sha256::digest(body.as_bytes())),
            depends_on: yara_dependencies(&body),
        })
        .collect()
}

pub(super) fn yara_blocks(text: &str) -> Vec<(String, String, bool)> {
    let bytes = text.as_bytes();
    let mut blocks = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if let Some(next) = skip_yara_gap(bytes, i) {
            i = next;
            continue;
        }
        if let Some((name, helper, end)) = yara_rule_at(text, i) {
            blocks.push((name, text[i..end].to_owned(), helper));
            i = end;
            continue;
        }
        i += 1;
    }
    blocks
}

/// Comments and quoted text are not code, so `rule` inside them is not a declaration.
fn skip_yara_gap(bytes: &[u8], index: usize) -> Option<usize> {
    let byte = *bytes.get(index)?;
    if byte == b'/' && bytes.get(index + 1) == Some(&b'/') {
        return Some(skip_line(bytes, index));
    }
    if byte == b'/' && bytes.get(index + 1) == Some(&b'*') {
        return Some(skip_block_comment(bytes, index));
    }
    if byte == b'"' || byte == b'\'' {
        return Some(skip_quoted(bytes, index));
    }
    None
}

fn yara_rule_at(text: &str, index: usize) -> Option<(String, bool, usize)> {
    let bytes = text.as_bytes();
    if index > 0 && is_yara_ident(bytes[index - 1]) {
        return None;
    }
    let mut cursor = index;
    let mut helper = false;
    for _ in 0..2 {
        if starts_with_word(bytes, cursor, b"private") {
            helper = true;
            cursor += "private".len();
            cursor = skip_horizontal(bytes, cursor);
        } else if starts_with_word(bytes, cursor, b"global") {
            cursor += "global".len();
            cursor = skip_horizontal(bytes, cursor);
        }
    }
    if !starts_with_word(bytes, cursor, b"rule") {
        return None;
    }
    cursor += "rule".len();
    cursor = skip_horizontal(bytes, cursor);
    let name_at = cursor;
    while cursor < bytes.len() && is_yara_ident(bytes[cursor]) {
        cursor += 1;
    }
    if name_at == cursor {
        return None;
    }
    let name = text.get(name_at..cursor)?.to_owned();
    let brace = find_rule_brace(bytes, cursor)?;
    let end = yara_rule_end(bytes, brace)?;
    Some((name, helper, end))
}

fn starts_with_word(bytes: &[u8], index: usize, word: &[u8]) -> bool {
    let Some(rest) = bytes.get(index..) else {
        return false;
    };
    rest.starts_with(word)
        && rest
            .get(word.len())
            .is_none_or(|next| !is_yara_ident(*next))
}

fn is_yara_ident(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn skip_horizontal(bytes: &[u8], mut index: usize) -> usize {
    while matches!(bytes.get(index), Some(b' ' | b'\t')) {
        index += 1;
    }
    index
}

fn find_rule_brace(bytes: &[u8], mut index: usize) -> Option<usize> {
    while index < bytes.len() {
        if let Some(next) = skip_yara_gap(bytes, index) {
            index = next;
            continue;
        }
        if bytes[index] == b'{' {
            return Some(index);
        }
        index += 1;
    }
    None
}

/// End index after the rule's closing brace. Comments, strings, regex literals
/// and hex strings do not change the brace depth.
fn yara_rule_end(bytes: &[u8], brace: usize) -> Option<usize> {
    let mut i = brace;
    let mut depth = 0i32;
    let mut last_code = 0u8;
    while i < bytes.len() {
        if let Some(next) = skip_yara_gap(bytes, i) {
            i = next;
            continue;
        }
        let byte = bytes[i];
        if byte == b'/' {
            i = skip_regex(bytes, i);
            last_code = b'/';
            continue;
        }
        if byte == b'{' && last_code == b'=' {
            i = skip_hex_string(bytes, i)?;
            last_code = b'}';
            continue;
        }
        if byte == b'{' {
            depth += 1;
        } else if byte == b'}' {
            depth -= 1;
            if depth == 0 {
                return Some(i + 1);
            }
        }
        if !byte.is_ascii_whitespace() {
            last_code = byte;
        }
        i += 1;
    }
    None
}

fn skip_line(bytes: &[u8], mut index: usize) -> usize {
    while index < bytes.len() && bytes[index] != b'\n' {
        index += 1;
    }
    index
}

fn skip_block_comment(bytes: &[u8], mut index: usize) -> usize {
    index += 2;
    while index + 1 < bytes.len() && !(bytes[index] == b'*' && bytes[index + 1] == b'/') {
        index += 1;
    }
    (index + 2).min(bytes.len())
}

fn skip_quoted(bytes: &[u8], mut index: usize) -> usize {
    let quote = bytes[index];
    index += 1;
    while index < bytes.len() && bytes[index] != quote {
        if bytes[index] == b'\\' {
            index += 1;
        }
        index += 1;
    }
    (index + 1).min(bytes.len())
}

fn skip_regex(bytes: &[u8], mut index: usize) -> usize {
    index += 1;
    let mut class = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'\\' {
            index += 2;
            continue;
        }
        if byte == b'[' && !class {
            class = true;
        } else if byte == b']' && class {
            class = false;
        } else if byte == b'/' && !class {
            return index + 1;
        } else if byte == b'\n' {
            return index;
        }
        index += 1;
    }
    index
}

fn skip_hex_string(bytes: &[u8], mut index: usize) -> Option<usize> {
    let mut depth = 0i32;
    while index < bytes.len() {
        if bytes[index] == b'{' {
            depth += 1;
        } else if bytes[index] == b'}' {
            depth -= 1;
            if depth == 0 {
                return Some(index + 1);
            }
        }
        index += 1;
    }
    None
}

fn yara_dependencies(body: &str) -> Vec<String> {
    let bytes = body.as_bytes();
    let Some(pos) = body.find("condition:") else {
        return Vec::new();
    };
    let mut i = pos + "condition:".len();
    let mut depth = 0i32;
    let mut names = Vec::new();
    while i < bytes.len() {
        if let Some(next) = skip_yara_gap(bytes, i) {
            i = next;
            continue;
        }
        let byte = bytes[i];
        if byte == b'{' {
            depth += 1;
            i += 1;
            continue;
        }
        if byte == b'}' {
            if depth == 0 {
                break;
            }
            depth -= 1;
            i += 1;
            continue;
        }
        if matches!(byte, b'$' | b'#' | b'@' | b'!') {
            i += 1;
            while i < bytes.len() && is_yara_ident(bytes[i]) {
                i += 1;
            }
            continue;
        }
        if byte.is_ascii_alphabetic() || byte == b'_' {
            let start = i;
            i += 1;
            while i < bytes.len() && is_yara_ident(bytes[i]) {
                i += 1;
            }
            push_dependency(&mut names, &body[start..i]);
            continue;
        }
        i += 1;
    }
    names.sort();
    names.dedup();
    names
}

fn push_dependency(names: &mut Vec<String>, token: &str) {
    const KEYWORDS: &[&str] = &[
        "and",
        "or",
        "not",
        "any",
        "all",
        "them",
        "of",
        "for",
        "in",
        "at",
        "filesize",
        "entrypoint",
        "true",
        "false",
        "defined",
        "matches",
        "contains",
        "icontains",
        "startswith",
        "istartswith",
        "endswith",
        "iendswith",
        "iequals",
        "uint8",
        "uint16",
        "uint32",
        "int8",
        "int16",
        "int32",
    ];
    if token.len() > 1
        && token
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic())
        && !KEYWORDS.contains(&token)
    {
        names.push(token.to_owned());
    }
}
