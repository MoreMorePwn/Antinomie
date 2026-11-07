// SPDX-License-Identifier: GPL-3.0-only
//! What kind of file a Files row is, from the first bytes the run captured of
//! it. Nothing is guessed from a name alone: a file with no captured content
//! is "unknown".

/// Octets of a file's start the type is read from.
pub const HEAD: usize = 64;

/// "ELF", "script", "archive", "config", "text", "data" or "unknown" for the
/// first bytes `head` of the file at `path`.
pub fn of(head: &[u8], path: &str) -> &'static str {
    if head.is_empty() {
        return "unknown";
    }
    if head.starts_with(b"\x7fELF") {
        return "ELF";
    }
    if head.starts_with(b"#!") {
        return "script";
    }
    if [
        &b"PK\x03\x04"[..],
        b"\x1f\x8b",
        b"BZh",
        b"\xfd7zXZ\0",
        b"Rar!",
        b"7z\xbc\xaf",
    ]
    .iter()
    .any(|magic| head.starts_with(magic))
    {
        return "archive";
    }
    let text = std::str::from_utf8(head)
        .map(|_| true)
        // A multi-byte character cut by the end of the head is still text.
        .unwrap_or_else(|error| error.error_len().is_none() && error.valid_up_to() > 0)
        && head
            .iter()
            .all(|byte| *byte >= 0x20 || matches!(byte, b'\n' | b'\r' | b'\t'));
    if !text {
        return "data";
    }
    if configuration(path) {
        "config"
    } else {
        "text"
    }
}

/// Whether the path is where, or named as, a configuration file.
pub fn configuration(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    let extension = name.rsplit_once('.').map(|(_, extension)| extension);
    path.starts_with("/etc/")
        || matches!(
            extension,
            Some(
                "conf"
                    | "cfg"
                    | "ini"
                    | "json"
                    | "yaml"
                    | "yml"
                    | "toml"
                    | "service"
                    | "timer"
                    | "desktop"
                    | "rules"
                    | "cnf"
                    | "env"
            )
        )
        || name.ends_with("rc")
}

#[cfg(test)]
pub mod tests {
    use super::of;

    #[test]
    fn the_first_bytes_name_the_kind() {
        assert_eq!(of(b"\x7fELF\x02\x01", "/tmp/x"), "ELF");
        assert_eq!(of(b"#!/bin/sh\nid\n", "/tmp/x"), "script");
        assert_eq!(of(b"PK\x03\x04rest", "/tmp/x.zip"), "archive");
        assert_eq!(of(b"hello\n", "/tmp/note"), "text");
        assert_eq!(of(b"key=value\n", "/etc/app.conf"), "config");
        assert_eq!(of(b"{\"a\":1}", "/etc/app/app.json"), "config");
        assert_eq!(of(b"\x00\x01\x02\x03", "/tmp/blob"), "data");
        assert_eq!(of(b"", "/tmp/x"), "unknown");
    }
}
