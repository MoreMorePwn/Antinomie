// SPDX-License-Identifier: GPL-3.0-only
//! The comparison key of a recorded path.

use std::borrow::Cow;

/// The path as a comparison key: repeated `/` and `.` segments collapsed, `..`
/// resolved lexically (never above `/`), no filesystem lookup. The recorded path
/// stays what is shown; only the key is normalised. A relative path keeps its
/// leading `..` segments.
pub fn path_key(path: &str) -> Cow<'_, str> {
    let plain = !path.contains("//")
        && (!path.ends_with('/') || path == "/")
        && !path.split('/').any(|part| part == "." || part == "..");
    if plain {
        return Cow::Borrowed(path);
    }
    let absolute = path.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if parts.last().is_some_and(|last| *last != "..") {
                    parts.pop();
                } else if !absolute {
                    parts.push("..");
                }
            }
            other => parts.push(other),
        }
    }
    let joined = parts.join("/");
    if absolute {
        Cow::Owned(format!("/{joined}"))
    } else if joined.is_empty() {
        Cow::Borrowed(".")
    } else {
        Cow::Owned(joined)
    }
}

#[cfg(test)]
mod tests {
    use super::path_key;

    #[test]
    fn collapses_dot_segments_lexically() {
        assert_eq!(path_key("/tmp/./w.bin"), "/tmp/w.bin");
        assert_eq!(path_key("/tmp/x/../w.bin"), "/tmp/w.bin");
        assert_eq!(path_key("/tmp//w.bin"), "/tmp/w.bin");
        assert_eq!(path_key("/../../bin/./busybox"), "/bin/busybox");
        assert_eq!(path_key("/"), "/");
        assert_eq!(path_key("/a/.."), "/");
        assert_eq!(path_key("/tmp/w.bin/"), "/tmp/w.bin");
        assert_eq!(path_key("a/../../b"), "../b");
        assert_eq!(path_key("/tmp/w.bin"), "/tmp/w.bin");
        assert_eq!(path_key("path unknown"), "path unknown");
    }
}
