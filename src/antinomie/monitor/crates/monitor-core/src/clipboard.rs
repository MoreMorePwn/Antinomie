// SPDX-License-Identifier: MIT
//! Bounded host text for typing through a US-layout virtual keyboard.

/// Maximum clipboard input in UTF-8 octets, before normalization.
pub const MAX_TEXT_SIZE: usize = 4096;
/// Text longer than this many keys needs an explicit UI confirmation.
pub const CONFIRM_KEY_COUNT: usize = 256;

#[derive(Debug)]
pub struct Text {
    /// Normalized, typeable text; no unsupported control characters.
    pub text: String,
    /// Number of virtual key chords, after normalization.
    pub key_count: usize,
    /// Unsupported Unicode/control characters omitted from the input.
    pub skipped_count: usize,
}

impl Text {
    /// Normalize line endings and omit characters unavailable on a US keyboard.
    ///
    /// | Argument / result | Meaning |
    /// |---|---|
    /// | `input` | Host clipboard text; never logged or persisted here. |
    /// | `Ok` | Bounded text and counts; unsupported characters are counted. |
    /// | `Err` | Empty, oversized or entirely unsupported text. |
    pub fn prepare(input: &str) -> Result<Self, String> {
        if input.len() > MAX_TEXT_SIZE {
            return Err(format!(
                "Clipboard exceeds the {MAX_TEXT_SIZE}-byte typing limit"
            ));
        }
        let mut text = String::new();
        let mut skipped_count = 0;
        for c in input.replace("\r\n", "\n").replace('\r', "\n").chars() {
            if key(c).is_some() {
                text.push(c);
            } else {
                skipped_count += 1;
            }
        }
        if text.is_empty() {
            return Err("Clipboard has no text that a US keyboard can type".into());
        }
        Ok(Self {
            key_count: text.len(),
            text,
            skipped_count,
        })
    }

    /// Whether typing is long or contains Enter keys (which can submit input).
    ///
    /// | Result | Meaning |
    /// |---|---|
    /// | `true` | UI must obtain confirmation before submitting this text. |
    pub fn needs_confirmation(&self) -> bool {
        self.key_count > CONFIRM_KEY_COUNT || self.text.contains('\n')
    }
}

pub(crate) fn key(c: char) -> Option<(String, bool)> {
    let (name, shift) = match c {
        'a'..='z' | '0'..='9' => (c.to_string(), false),
        'A'..='Z' => (c.to_ascii_lowercase().to_string(), true),
        '\n' => ("ret".into(), false),
        '\t' => ("tab".into(), false),
        ' ' => ("spc".into(), false),
        _ => {
            for (plain, shifted, name) in [
                ('`', '~', "grave_accent"),
                ('-', '_', "minus"),
                ('=', '+', "equal"),
                ('[', '{', "bracket_left"),
                (']', '}', "bracket_right"),
                ('\\', '|', "backslash"),
                (';', ':', "semicolon"),
                ('\'', '"', "apostrophe"),
                (',', '<', "comma"),
                ('.', '>', "dot"),
                ('/', '?', "slash"),
                ('1', '!', "1"),
                ('2', '@', "2"),
                ('3', '#', "3"),
                ('4', '$', "4"),
                ('5', '%', "5"),
                ('6', '^', "6"),
                ('7', '&', "7"),
                ('8', '*', "8"),
                ('9', '(', "9"),
                ('0', ')', "0"),
            ] {
                if c == plain || c == shifted {
                    return Some((name.into(), c == shifted));
                }
            }
            return None;
        }
    };
    Some((name, shift))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn printable_us_text_line_endings_and_unsupported_characters() {
        for c in ' '..='~' {
            assert!(key(c).is_some(), "{c}");
        }
        let text = Text::prepare("Hello\r\nworld\ré🙂\0\u{1b}").unwrap();
        assert_eq!(text.text, "Hello\nworld\n");
        assert_eq!(text.skipped_count, 4);
        assert!(text.needs_confirmation());
        assert_eq!(key('@'), Some(("2".into(), true)));
        assert_eq!(key('A'), Some(("a".into(), true)));
        assert!(Text::prepare("").is_err());
        assert!(Text::prepare("🙂").is_err());
        assert!(Text::prepare(&"a".repeat(MAX_TEXT_SIZE + 1)).is_err());
        assert!(!Text::prepare("hello").unwrap().needs_confirmation());
        assert!(
            Text::prepare(&"a".repeat(257))
                .unwrap()
                .needs_confirmation()
        );
    }
}
