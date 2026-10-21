// SPDX-License-Identifier: MIT
//! Public MalShare API metadata retrieved 2026-10-18; lists limited to three rows.
//! Endpoint contract: https://malshare.com/doc.php. No key or sample bodies retained.
use super::*;
use std::path::PathBuf;

#[test]
fn actual_metadata_replies_fill_rows_and_preserve_empty_results() {
    assert_eq!(
        type_name(include_bytes!("fixtures/types.json"), "elf").unwrap(),
        Some("ELF".into())
    );
    assert_eq!(
        infos(include_bytes!("fixtures/list.json"), None, 1000)
            .unwrap()
            .len(),
        3
    );
    let elf = infos(include_bytes!("fixtures/elf.json"), Some("ELF"), 1000).unwrap();
    assert_eq!(elf.len(), 3);
    assert!(elf.iter().all(|info| info.is_elf()));
    let details = infos(include_bytes!("fixtures/details.json"), None, 1).unwrap();
    assert_eq!(details[0].file_name, "KryptonPlus-1.21.11.jar");
    assert_eq!(details[0].file_size, 3016129);
    assert_eq!(details[0].file_type, "zip");
    let search = infos(include_bytes!("fixtures/search-hash.json"), None, 10).unwrap();
    assert_eq!(search.len(), 1);
    assert!(!search[0].first_seen.is_empty());
    assert!(
        infos(include_bytes!("fixtures/no-match.json"), None, 100)
            .unwrap()
            .is_empty()
    );
    for invalid in [
        b"{}".as_slice(),
        b"null",
        b"[null]",
        br#"{"error":"quota"}"#,
        br#"[{"sha256":"bad"}]"#,
        b"[{",
        b"<html>Denied</html>",
    ] {
        assert!(infos(invalid, None, 10).is_err(), "{invalid:?}");
    }
    assert!(type_name(br#"{"error":"denied"}"#, "elf").is_err());
    let hash = "a".repeat(64);
    let other = "b".repeat(64);
    let reply = format!(r#"["{hash}","{hash}","{other}"]"#);
    assert_eq!(infos(reply.as_bytes(), None, 2).unwrap().len(), 2);
}

/// Write `body` as an executable script at a path of its own. A path that was
/// executed is never rewritten: the kernel refuses to exec a file some process
/// still holds open for writing (ETXTBSY), and a test process full of threads
/// that fork children inherits such descriptors for a moment.
pub(super) fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join(name);
    std::fs::write(&path, body).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    path
}

/// Run `attempt` again while it fails only because another thread's child
/// briefly held the script open for writing.
pub(super) fn retry_busy<T>(mut attempt: impl FnMut() -> Result<T, String>) -> Result<T, String> {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while std::time::Instant::now() < deadline {
        match attempt() {
            Err(error) if error.contains("Text file busy") => {
                std::thread::sleep(Duration::from_millis(10))
            }
            result => return result,
        }
    }
    attempt()
}

#[test]
fn http_failures_and_stderr_do_not_disclose_the_key() {
    let root = std::env::temp_dir().join(format!("ant-share-http-{}", crate::storage::unique_id()));
    std::fs::create_dir_all(&root).unwrap();
    for (case, (body, expected)) in [
        (
            "#!/bin/sh\ncat >/dev/null\nprintf 'denied\\n403'\n",
            "HTTP 403",
        ),
        (
            "#!/bin/sh\ncat >/dev/null\nprintf 'rate limit\\n429'\n",
            "HTTP 429",
        ),
        (
            "#!/bin/sh\ncat >/dev/null\nprintf 'temporarysecret' >&2\nexit 7\n",
            "[redacted]",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let curl = script(&root, &format!("curl-{case}"), body);
        let error = retry_busy(|| {
            get(
                &curl,
                "temporarysecret",
                &[("action", "getlist")],
                MAX_REPLY,
            )
        })
        .unwrap_err();
        assert!(error.contains(expected), "{error}");
        assert!(!error.contains("temporarysecret"));
    }
    let curl = script(
        &root,
        "curl-empty",
        "#!/bin/sh\ncat >/dev/null\nprintf '[]\\n200'\n",
    );
    assert_eq!(
        retry_busy(|| get(&curl, "temporarysecret", &[], MAX_REPLY)).unwrap(),
        b"[]"
    );
    // File bytes ending with a newline are preserved exactly, not trimmed.
    let curl = script(
        &root,
        "curl-file",
        "#!/bin/sh\ncat >/dev/null\nprintf 'file\\n\\n200'\n",
    );
    assert_eq!(
        retry_busy(|| get(
            &curl,
            "temporarysecret",
            &[("action", "getfile")],
            MAX_REPLY
        ))
        .unwrap(),
        b"file\n"
    );
    std::fs::remove_dir_all(root).unwrap();
}
