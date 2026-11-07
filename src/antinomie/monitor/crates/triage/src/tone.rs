// SPDX-License-Identifier: GPL-3.0-only
//! The colour roles of the text in Triage rows. A row says what a piece of
//! text is (an error, a note, a syscall name); the UI picks the colour from
//! the theme that is active when the row is drawn.
use serde::{Deserialize, Serialize};

/// What a value is, for its syntax colour.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ValueKind {
    Number,
    Text,
    Pointer,
    Flags,
    /// Syscall and symbol names.
    Name,
    Error,
    Plain,
}

/// The role of a piece of text or of a chip.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Tone {
    /// Body text.
    Text,
    /// Secondary text, "nothing to see" and INFO.
    Muted,
    Good,
    Warn,
    /// An error, or a HIGH finding.
    Bad,
    /// A LOW finding, a known false positive: the blue of links.
    Info,
    /// A value shown in its syntax colour.
    Value(ValueKind),
    /// The neutral accent of the theme.
    Accent,
    /// The primary colour of the theme.
    Primary,
    /// The call-to-action blue.
    BrightBlue,
    /// The theme's information colour.
    Notice,
}

pub fn text() -> Tone {
    Tone::Text
}
pub fn muted() -> Tone {
    Tone::Muted
}
pub fn good() -> Tone {
    Tone::Good
}
pub fn warn() -> Tone {
    Tone::Warn
}
pub fn error() -> Tone {
    Tone::Bad
}
pub fn blue() -> Tone {
    Tone::Info
}
pub fn value(kind: ValueKind) -> Tone {
    Tone::Value(kind)
}
