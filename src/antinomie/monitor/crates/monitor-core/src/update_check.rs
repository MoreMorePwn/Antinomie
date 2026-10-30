// SPDX-License-Identifier: GPL-3.0-only
//! Asking GitHub whether a newer Antinomie release exists. It runs only when
//! the person asks: one request for the latest release, nothing is downloaded
//! or installed, and the answer is a version and a link to the release page.
use serde_json::Value;
use std::{
    cmp::Ordering,
    io::Read,
    path::Path,
    process::Stdio,
    sync::atomic::{AtomicBool, Ordering as AtomicOrdering},
    time::{Duration, Instant},
};

/// The project's page; release pages live under it.
pub const REPOSITORY_URL: &str = "https://github.com/MoreMorePwn/Antinomie";
/// The latest published (not draft, not pre-release) release.
pub const LATEST_RELEASE_URL: &str =
    "https://api.github.com/repos/MoreMorePwn/Antinomie/releases/latest";
/// Largest reply read; a release description is a few kilobytes.
const MAX_REPLY: u64 = 1024 * 1024;
const TIMEOUT: u32 = 20;

/// The latest release as GitHub describes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Release {
    /// The tag as published, for example `v0.8.1`.
    pub tag: String,
    /// The tag without a leading `v`.
    pub version: String,
    /// The release page, always on the project's own pages.
    pub url: String,
}

/// How the running version compares with the latest release.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UpdateStatus {
    /// A newer version has been released.
    Newer(Release),
    /// The running version is the latest.
    Current(Release),
    /// The running version is newer than the latest release (a build in
    /// development).
    Ahead(Release),
}

/// One HTTP answer: the status code and the body.
pub struct Reply {
    pub status: u16,
    pub body: String,
}

/// Fetches one URL with a GET.
pub trait Get {
    fn get(&self, url: &str, cancel: &AtomicBool) -> Result<Reply, String>;
}

/// The system `curl`, with the shared download hardening.
pub struct CurlGet<'a> {
    pub curl: &'a Path,
}

impl Get for CurlGet<'_> {
    fn get(&self, url: &str, cancel: &AtomicBool) -> Result<Reply, String> {
        crate::dependencies::require_tool(self.curl, "curl")?;
        let mut command = crate::http_fetch::command(
            self.curl,
            &crate::http_fetch::Options {
                fail: false,
                ..crate::http_fetch::Options::new(TIMEOUT, MAX_REPLY)
            },
        );
        let mut child = command
            .args([
                "--header",
                "Accept: application/vnd.github+json",
                "--header",
                "X-GitHub-Api-Version: 2022-11-28",
                "--user-agent",
                concat!("Antinomie/", env!("CARGO_PKG_VERSION")),
                "--write-out",
                "\n%{http_code}",
            ])
            .arg(url)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| format!("curl: {error}"))?;
        // The reader threads let the loop below watch the cancel flag.
        let mut stdout = child.stdout.take();
        let mut stderr = child.stderr.take();
        let out = std::thread::spawn(move || {
            let mut reply = Vec::new();
            if let Some(stdout) = stdout.as_mut() {
                let _ = stdout.take(MAX_REPLY + 8).read_to_end(&mut reply);
            }
            reply
        });
        let err = std::thread::spawn(move || {
            let mut text = String::new();
            if let Some(stderr) = stderr.as_mut() {
                let _ = stderr.take(4096).read_to_string(&mut text);
            }
            text
        });
        let started = Instant::now();
        let status = loop {
            if cancel.load(AtomicOrdering::Relaxed) {
                let _ = child.kill();
                let _ = child.wait();
                return Err("cancelled".into());
            }
            match child.try_wait().map_err(|error| error.to_string())? {
                Some(status) => break status,
                None if started.elapsed() > Duration::from_secs(u64::from(TIMEOUT) + 10) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err("the request timed out".into());
                }
                None => std::thread::sleep(Duration::from_millis(50)),
            }
        };
        let reply = out.join().unwrap_or_default();
        let message = err.join().unwrap_or_default();
        if !status.success() {
            return Err(offline_text(message.lines().last().unwrap_or("").trim()));
        }
        split_reply(&reply)
    }
}

/// The body and the status code `--write-out` appended after a newline.
fn split_reply(reply: &[u8]) -> Result<Reply, String> {
    let at = reply
        .iter()
        .rposition(|byte| *byte == b'\n')
        .ok_or("GitHub gave no HTTP status")?;
    let status = std::str::from_utf8(&reply[at + 1..])
        .ok()
        .and_then(|code| code.trim().parse().ok())
        .ok_or("GitHub gave an invalid HTTP status")?;
    Ok(Reply {
        status,
        body: String::from_utf8_lossy(&reply[..at]).into_owned(),
    })
}

/// What a failed connection means, in words.
fn offline_text(reason: &str) -> String {
    if reason.is_empty() {
        "Could not reach GitHub. Check the network connection and try again.".into()
    } else {
        format!("Could not reach GitHub ({reason}). Check the network connection and try again.")
    }
}

/// Ask for the latest release and compare it with `current`.
pub fn check(current: &str, getter: &dyn Get, cancel: &AtomicBool) -> Result<UpdateStatus, String> {
    let reply = getter.get(LATEST_RELEASE_URL, cancel)?;
    match reply.status {
        200 => {}
        403 | 429 => {
            return Err(
                "GitHub is limiting requests from this address (HTTP 403 or 429). Try again later."
                    .into(),
            );
        }
        404 => return Err("No release has been published yet.".into()),
        500..=599 => {
            return Err(format!(
                "GitHub had a problem answering (HTTP {}). Try again later.",
                reply.status
            ));
        }
        other => return Err(format!("GitHub answered HTTP {other}.")),
    }
    let release = parse_release(&reply.body)?;
    status(current, release)
}

/// Compare `current` with `release`.
pub fn status(current: &str, release: Release) -> Result<UpdateStatus, String> {
    let current = Version::parse(current)
        .ok_or_else(|| format!("This version ({current}) is not a version number."))?;
    let latest = Version::parse(&release.version).ok_or_else(|| {
        format!(
            "The latest release is tagged {}, which is not a version number.",
            release.tag
        )
    })?;
    Ok(match latest.cmp(&current) {
        Ordering::Greater => UpdateStatus::Newer(release),
        Ordering::Equal => UpdateStatus::Current(release),
        Ordering::Less => UpdateStatus::Ahead(release),
    })
}

/// Read the release GitHub's "latest release" answer describes. Only the tag
/// is needed; the page link is GitHub's own `html_url` when it is on the
/// project's pages, and otherwise built from the tag.
pub fn parse_release(body: &str) -> Result<Release, String> {
    let value: Value = serde_json::from_str(body)
        .map_err(|_| "GitHub's answer was not understood (it is not JSON).".to_owned())?;
    let tag = value
        .get("tag_name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|tag| !tag.is_empty())
        .ok_or("GitHub's answer was not understood (it names no release tag).")?;
    if tag.len() > 64
        || tag
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || c == '/')
    {
        return Err("GitHub's answer was not understood (the release tag is invalid).".into());
    }
    let own_page = format!("{REPOSITORY_URL}/releases/");
    let url = value
        .get("html_url")
        .and_then(Value::as_str)
        .filter(|url| url.starts_with(&own_page) && !url.chars().any(char::is_control))
        .map_or_else(|| format!("{own_page}tag/{tag}"), str::to_owned);
    Ok(Release {
        tag: tag.to_owned(),
        version: tag.strip_prefix(['v', 'V']).unwrap_or(tag).to_owned(),
        url,
    })
}

/// A version number: dot-separated numbers, then an optional pre-release
/// (`-rc.1`); build metadata (`+...`) is ignored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Version {
    numbers: Vec<u64>,
    pre: Vec<Part>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Part {
    Number(u64),
    Text(String),
}

impl Version {
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        let text = text.strip_prefix(['v', 'V']).unwrap_or(text);
        let text = text.split('+').next()?;
        let (core, pre) = match text.split_once('-') {
            Some((core, pre)) => (core, Some(pre)),
            None => (text, None),
        };
        let mut numbers = core
            .split('.')
            .map(|part| {
                (!part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
                    .then(|| part.parse().ok())
                    .flatten()
            })
            .collect::<Option<Vec<u64>>>()?;
        if numbers.is_empty() || numbers.len() > 4 {
            return None;
        }
        // 0.8 and 0.8.0 are the same version.
        while numbers.len() > 1 && numbers.last() == Some(&0) {
            numbers.pop();
        }
        let pre = match pre {
            None => Vec::new(),
            Some(pre) => pre
                .split('.')
                .map(|part| {
                    if part.is_empty() || !part.bytes().all(|b| b.is_ascii_alphanumeric()) {
                        None
                    } else if part.bytes().all(|b| b.is_ascii_digit()) {
                        part.parse().ok().map(Part::Number)
                    } else {
                        Some(Part::Text(part.to_ascii_lowercase()))
                    }
                })
                .collect::<Option<Vec<_>>>()?,
        };
        Some(Self { numbers, pre })
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        let length = self.numbers.len().max(other.numbers.len());
        for at in 0..length {
            let a = self.numbers.get(at).copied().unwrap_or(0);
            let b = other.numbers.get(at).copied().unwrap_or(0);
            match a.cmp(&b) {
                Ordering::Equal => {}
                different => return different,
            }
        }
        // A pre-release is older than the release it leads to.
        match (self.pre.is_empty(), other.pre.is_empty()) {
            (true, true) => Ordering::Equal,
            (true, false) => Ordering::Greater,
            (false, true) => Ordering::Less,
            (false, false) => self.pre.cmp(&other.pre),
        }
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialOrd for Part {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Part {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Part::Number(a), Part::Number(b)) => a.cmp(b),
            (Part::Text(a), Part::Text(b)) => a.cmp(b),
            // Numbers rank below text, as in SemVer.
            (Part::Number(_), Part::Text(_)) => Ordering::Less,
            (Part::Text(_), Part::Number(_)) => Ordering::Greater,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version(text: &str) -> Version {
        Version::parse(text).unwrap_or_else(|| panic!("{text} should parse"))
    }

    struct Canned(Result<(u16, &'static str), &'static str>);

    impl Get for Canned {
        fn get(&self, url: &str, _: &AtomicBool) -> Result<Reply, String> {
            assert_eq!(url, LATEST_RELEASE_URL);
            self.0
                .map(|(status, body)| Reply {
                    status,
                    body: body.into(),
                })
                .map_err(str::to_owned)
        }
    }

    fn run(current: &str, canned: Canned) -> Result<UpdateStatus, String> {
        check(current, &canned, &AtomicBool::new(false))
    }

    #[test]
    fn versions_compare_by_number_not_by_text() {
        assert!(version("0.8.1") > version("0.8.0"));
        assert!(version("0.10.0") > version("0.9.9"));
        assert!(version("1.0.0") > version("0.99.99"));
        assert_eq!(version("v0.8.0"), version("0.8.0"));
        assert_eq!(version("0.8"), version("0.8.0"));
        assert_eq!(
            version("0.8.0+build5").cmp(&version("0.8.0")),
            Ordering::Equal
        );
    }

    #[test]
    fn a_pre_release_is_older_than_its_release() {
        assert!(version("0.9.0-rc.1") < version("0.9.0"));
        assert!(version("0.9.0-rc.2") > version("0.9.0-rc.1"));
        assert!(version("0.9.0-rc.10") > version("0.9.0-rc.2"));
        assert!(version("0.9.0-rc.1") > version("0.8.9"));
        assert!(version("0.9.0-beta") < version("0.9.0-rc"));
    }

    #[test]
    fn text_that_is_not_a_version_is_refused() {
        for text in [
            "",
            "latest",
            "1..2",
            "1.x",
            "0.8.0-",
            "0.8.0-a_b",
            "1.2.3.4.5",
            "-1",
        ] {
            assert!(Version::parse(text).is_none(), "{text:?}");
        }
    }

    #[test]
    fn a_release_answer_gives_the_tag_and_the_project_page() {
        let release = parse_release(
            r#"{"tag_name":"v0.8.1","name":"x","html_url":"https://github.com/MoreMorePwn/Antinomie/releases/tag/v0.8.1","draft":false}"#,
        )
        .unwrap();
        assert_eq!(release.tag, "v0.8.1");
        assert_eq!(release.version, "0.8.1");
        assert_eq!(
            release.url,
            "https://github.com/MoreMorePwn/Antinomie/releases/tag/v0.8.1"
        );
    }

    #[test]
    fn a_link_outside_the_project_is_replaced_by_one_built_from_the_tag() {
        let release =
            parse_release(r#"{"tag_name":"0.8.1","html_url":"https://example.org/phish"}"#)
                .unwrap();
        assert_eq!(release.version, "0.8.1");
        assert_eq!(
            release.url,
            "https://github.com/MoreMorePwn/Antinomie/releases/tag/0.8.1"
        );
        let missing = parse_release(r#"{"tag_name":"v1.0.0"}"#).unwrap();
        assert!(missing.url.starts_with(REPOSITORY_URL));
    }

    #[test]
    fn malformed_answers_are_named() {
        for body in [
            "",
            "<html>rate limited</html>",
            "[]",
            "{}",
            r#"{"tag_name":""}"#,
            r#"{"tag_name":42}"#,
            r#"{"tag_name":"v1 0"}"#,
            r#"{"tag_name":"a/b"}"#,
        ] {
            let error = parse_release(body).unwrap_err();
            assert!(error.contains("not understood"), "{body:?}: {error}");
        }
    }

    #[test]
    fn the_answer_says_whether_a_newer_version_exists() {
        let body = r#"{"tag_name":"v0.8.1"}"#;
        assert!(matches!(
            run("0.8.0", Canned(Ok((200, body)))),
            Ok(UpdateStatus::Newer(release)) if release.version == "0.8.1"
        ));
        assert!(matches!(
            run("0.8.1", Canned(Ok((200, body)))),
            Ok(UpdateStatus::Current(_))
        ));
        assert!(matches!(
            run("0.9.0", Canned(Ok((200, body)))),
            Ok(UpdateStatus::Ahead(_))
        ));
    }

    #[test]
    fn a_tag_that_is_not_a_version_is_reported_not_guessed() {
        let error = run("0.8.0", Canned(Ok((200, r#"{"tag_name":"nightly"}"#)))).unwrap_err();
        assert!(error.contains("nightly"), "{error}");
    }

    #[test]
    fn http_errors_and_offline_give_clear_messages() {
        let limited = run("0.8.0", Canned(Ok((403, "{}")))).unwrap_err();
        assert!(limited.contains("limiting"), "{limited}");
        assert!(
            run("0.8.0", Canned(Ok((429, ""))))
                .unwrap_err()
                .contains("limiting")
        );
        assert!(
            run("0.8.0", Canned(Ok((404, ""))))
                .unwrap_err()
                .contains("No release")
        );
        assert!(
            run("0.8.0", Canned(Ok((502, ""))))
                .unwrap_err()
                .contains("502")
        );
        assert!(
            run("0.8.0", Canned(Ok((301, ""))))
                .unwrap_err()
                .contains("301")
        );
        assert_eq!(
            run("0.8.0", Canned(Err("Could not reach GitHub."))).unwrap_err(),
            "Could not reach GitHub."
        );
    }

    #[test]
    fn the_status_code_is_split_from_the_body() {
        let reply = split_reply(b"{\"a\":1}\n200").unwrap();
        assert_eq!((reply.status, reply.body.as_str()), (200, "{\"a\":1}"));
        assert!(split_reply(b"no status").is_err());
        assert!(split_reply(b"body\nabc").is_err());
        assert!(offline_text("").contains("Could not reach"));
        assert!(offline_text("Could not resolve host: api.github.com").contains("resolve host"));
    }
}
