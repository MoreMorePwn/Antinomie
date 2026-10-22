// SPDX-License-Identifier: GPL-3.0-only
//! A small, bounded glob matcher for Find: `*` (any run, including `/`),
//! `?` (one character) and `[...]` classes (ranges, leading `!` or `^`
//! negates). Case-insensitive. Matching is iterative with backtracking only
//! to the last `*`, so it is linear-ish and cannot blow up.

/// Whether `text` matches `pattern`.
pub fn matches(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().flat_map(char::to_lowercase).collect();
    let text: Vec<char> = text.chars().flat_map(char::to_lowercase).collect();
    let (mut p, mut t) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while t < text.len() {
        let step = match pattern.get(p) {
            Some('*') => {
                star = Some((p, t));
                p += 1;
                continue;
            }
            Some('?') => Some(p + 1),
            Some('[') => class(&pattern, p, text[t]).or_else(|| unclosed(&pattern, p, text[t])),
            Some(&c) if c == text[t] => Some(p + 1),
            _ => None,
        };
        match step {
            Some(next) => {
                p = next;
                t += 1;
            }
            None => match star {
                Some((star_p, star_t)) => {
                    p = star_p + 1;
                    t = star_t + 1;
                    star = Some((star_p, star_t + 1));
                }
                None => return false,
            },
        }
    }
    while pattern.get(p) == Some(&'*') {
        p += 1;
    }
    p == pattern.len()
}

/// A `[` with no closing `]` matches itself.
fn unclosed(pattern: &[char], start: usize, c: char) -> Option<usize> {
    (c == '[' && !pattern[start..].contains(&']')).then_some(start + 1)
}

/// The pattern position after a `[...]` class that matches `c`, or `None`
/// when it does not (or the class is not closed: then `[` is a literal).
fn class(pattern: &[char], start: usize, c: char) -> Option<usize> {
    let mut i = start + 1;
    let negate = matches!(pattern.get(i), Some('!' | '^'));
    if negate {
        i += 1;
    }
    let first = i;
    let mut found = false;
    loop {
        let low = *pattern.get(i)?;
        if low == ']' && i > first {
            return (found != negate).then_some(i + 1);
        }
        if pattern.get(i + 1) == Some(&'-') && pattern.get(i + 2).is_some_and(|c| *c != ']') {
            let high = pattern[i + 2];
            found |= low <= c && c <= high;
            i += 3;
        } else {
            found |= low == c;
            i += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::matches;

    #[test]
    fn wildcards_classes_and_case() {
        assert!(matches("*.so", "libc.so"));
        assert!(matches("*.SO", "libc.so"));
        assert!(!matches("*.so", "libc.so.6"));
        assert!(matches("*.so*", "libc.so.6"));
        assert!(matches("/etc/*", "/etc/cron.d/x"));
        assert!(matches("l?bc.so", "libc.so"));
        assert!(matches("[a-c]at", "bat"));
        assert!(!matches("[!a-c]at", "bat"));
        assert!(matches("[!a-c]at", "rat"));
        assert!(matches("a[", "a["));
        assert!(matches("*", ""));
        assert!(!matches("?", ""));
    }

    #[test]
    fn pathological_patterns_stay_fast() {
        let text = "a".repeat(10_000);
        assert!(!matches(&format!("{}b", "*a".repeat(50)), &text));
    }
}
