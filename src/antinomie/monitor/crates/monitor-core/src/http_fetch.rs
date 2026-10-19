// SPDX-License-Identifier: MIT
//! The one place that builds a `curl` command line for a download.
//!
//! Every front-end (MalShare, MalwareBazaar, the base and tool downloads, the
//! Debian image, the rule catalog) starts from [`command`], so they share the
//! same hardening: the user's `~/.curlrc` is ignored, only HTTPS is spoken (also
//! for redirects), redirects and transfer sizes are bounded, connections and
//! transfers have deadlines, and certificate checks are never disabled.
use std::{path::Path, process::Command};

/// Redirects followed when a caller asks to follow them.
pub(crate) const MAX_REDIRECTS: u32 = 3;

/// Per-call limits. Everything else is fixed.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Options {
    /// Seconds to establish a connection.
    pub connect_timeout: u32,
    /// Seconds one transfer may take; `None` leaves a long download to the
    /// caller's stall detection (`--speed-limit`).
    pub max_time: Option<u32>,
    /// Largest body accepted, checked against the announced length.
    pub max_filesize: Option<u64>,
    /// Treat HTTP errors as failures (`--fail`). Callers that report the HTTP
    /// status themselves turn this off.
    pub fail: bool,
    /// Follow redirects (to HTTPS only, at most [`MAX_REDIRECTS`]).
    pub follow: bool,
}

impl Options {
    pub(crate) const fn new(max_time: u32, max_filesize: u64) -> Self {
        Self {
            connect_timeout: 30,
            max_time: Some(max_time),
            max_filesize: Some(max_filesize),
            fail: true,
            follow: false,
        }
    }
}

/// Protocols a request may start with: HTTPS only. Tests alone also allow
/// `file://`, so download code can be exercised without a network.
const fn protocols() -> &'static str {
    if cfg!(test) { "=https,file" } else { "=https" }
}

/// The hardening arguments, in the order they are given to curl.
/// `--disable` must come first for curl to honour it.
pub(crate) fn args(options: &Options) -> Vec<String> {
    let mut args: Vec<String> = [
        "--disable",
        "--silent",
        "--show-error",
        "--proto",
        protocols(),
        "--proto-redir",
        "=https",
    ]
    .map(String::from)
    .into();
    args.extend([
        "--connect-timeout".into(),
        options.connect_timeout.to_string(),
    ]);
    if let Some(seconds) = options.max_time {
        args.extend(["--max-time".into(), seconds.to_string()]);
    }
    if let Some(size) = options.max_filesize {
        args.extend(["--max-filesize".into(), size.to_string()]);
    }
    if options.fail {
        args.push("--fail".into());
    }
    if options.follow {
        args.extend(["--location".into(), "--max-redirs".into()]);
        args.push(MAX_REDIRECTS.to_string());
    }
    args
}

/// A `curl` command that already carries the shared hardening.
pub(crate) fn command(curl: &Path, options: &Options) -> Command {
    let mut command = Command::new(curl);
    command.args(args(options));
    command
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_fetch_is_https_only_bounded_and_ignores_curlrc() {
        let args = args(&Options {
            follow: true,
            ..Options::new(30, 1024)
        });
        assert_eq!(args[0], "--disable");
        for pair in [
            ["--proto-redir", "=https"],
            ["--max-time", "30"],
            ["--max-filesize", "1024"],
            ["--max-redirs", "3"],
        ] {
            assert!(
                args.windows(2).any(|w| w == pair),
                "{pair:?} missing from {args:?}"
            );
        }
        for flag in ["--fail", "--location", "--connect-timeout"] {
            assert!(args.iter().any(|a| a == flag), "{flag}");
        }
        assert!(
            args.windows(2)
                .any(|w| w[0] == "--proto" && w[1].starts_with("=https"))
        );
        assert!(!args.iter().any(|a| a == "-k" || a == "--insecure"));
        let plain = super::args(&Options {
            fail: false,
            max_time: None,
            max_filesize: None,
            ..Options::new(1, 1)
        });
        assert!(!plain.iter().any(|a| a == "--location" || a == "--fail"));
    }
}
