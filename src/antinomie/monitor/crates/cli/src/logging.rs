// SPDX-License-Identifier: GPL-3.0-only
//! Log lines on standard error (design 2.6): `text` or one JSON object per
//! line. Results never go through here.
use crate::args::{Global, LogFormat};
use serde_json::json;
use std::io::Write;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl Level {
    fn upper(self) -> &'static str {
        match self {
            Level::Error => "ERROR",
            Level::Warn => "WARN",
            Level::Info => "INFO",
            Level::Debug => "DEBUG",
            Level::Trace => "TRACE",
        }
    }

    fn lower(self) -> &'static str {
        match self {
            Level::Error => "error",
            Level::Warn => "warn",
            Level::Info => "info",
            Level::Debug => "debug",
            Level::Trace => "trace",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Logger {
    pub level: Level,
    pub format: LogFormat,
}

impl Logger {
    pub fn from_global(global: &Global) -> Self {
        let level = if global.quiet {
            Level::Error
        } else {
            match global.verbose {
                0 => Level::Info,
                1 => Level::Debug,
                _ => Level::Trace,
            }
        };
        Self {
            level,
            format: global.log_format,
        }
    }

    pub fn enabled(&self, level: Level) -> bool {
        level <= self.level
    }

    /// The line for a message, or `None` when the level is filtered out.
    pub fn line(&self, level: Level, ts_ms: u64, message: &str) -> Option<String> {
        if !self.enabled(level) {
            return None;
        }
        let message = strip_controls(message);
        Some(match self.format {
            LogFormat::Text => format!("{} {} msg={message:?}", iso_time(ts_ms), level.upper()),
            LogFormat::Json => json!({
                "ts_ms": ts_ms,
                "level": level.lower(),
                "msg": message,
            })
            .to_string(),
        })
    }

    pub fn log(&self, level: Level, message: &str) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64);
        if let Some(line) = self.line(level, now, message) {
            let _ = writeln!(std::io::stderr(), "{line}");
        }
    }

    pub fn debug(&self, message: &str) {
        self.log(Level::Debug, message);
    }

    pub fn info(&self, message: &str) {
        self.log(Level::Info, message);
    }

    pub fn warn(&self, message: &str) {
        self.log(Level::Warn, message);
    }
}

/// Control characters would let a sample name forge log lines.
fn strip_controls(text: &str) -> String {
    text.chars().filter(|c| !c.is_control()).collect()
}

/// `2026-10-31T12:00:00.123Z`.
pub fn iso_time(ts_ms: u64) -> String {
    let seconds = (ts_ms / 1000) as i64;
    let (year, month, day) =
        antinomie_monitor_core::date::civil_from_days(seconds.div_euclid(86_400));
    let rest = seconds.rem_euclid(86_400);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60,
        ts_ms % 1000
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn logger(level: Level, format: LogFormat) -> Logger {
        Logger { level, format }
    }

    #[test]
    fn time_is_iso_utc_with_milliseconds() {
        assert_eq!(iso_time(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso_time(1_793_448_000_123), "2026-10-31T12:00:00.123Z");
    }

    #[test]
    fn text_and_json_lines() {
        let text = logger(Level::Info, LogFormat::Text)
            .line(Level::Info, 0, "run started")
            .unwrap();
        assert_eq!(text, "1970-01-01T00:00:00.000Z INFO msg=\"run started\"");
        let json = logger(Level::Info, LogFormat::Json)
            .line(Level::Warn, 5, "x")
            .unwrap();
        assert_eq!(json, r#"{"ts_ms":5,"level":"warn","msg":"x"}"#);
    }

    #[test]
    fn levels_filter_and_controls_are_stripped() {
        let info = logger(Level::Info, LogFormat::Text);
        assert!(info.line(Level::Debug, 0, "x").is_none());
        let line = info.line(Level::Error, 0, "a\nb\x1b[0m").unwrap();
        assert!(!line.contains('\n') && !line.contains('\x1b'));
    }

    #[test]
    fn quiet_and_verbose_select_the_level() {
        use crate::args::Cli;
        use clap::Parser;
        let level = |args: &[&str]| {
            let mut all = vec!["antinomie-cli"];
            all.extend_from_slice(args);
            all.push("doctor");
            Logger::from_global(&Cli::try_parse_from(all).unwrap().global).level
        };
        assert_eq!(level(&[]), Level::Info);
        assert_eq!(level(&["-q"]), Level::Error);
        assert_eq!(level(&["-v"]), Level::Debug);
        assert_eq!(level(&["-vv"]), Level::Trace);
    }
}
