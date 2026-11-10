// SPDX-License-Identifier: GPL-3.0-only
//! Where the daemon's log lines go (`service.toml [log] file`, design 2.6):
//! stderr, or a file of mode 0600 that rotates at 10 MiB and keeps 5 files
//! (`daemon.log`, `daemon.log.1` .. `daemon.log.4`).
use crate::logging::{Level, Logger};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::Mutex,
};

/// A file rotates when a line would take it past this.
pub const ROTATE_AT: u64 = 10 * 1024 * 1024;
/// Files kept, the live one included.
pub const KEEP: usize = 5;

/// The lines the audit log writes (design 5.12.7); they pass every level,
/// because an audit trail that `level = "error"` or `-q` can switch off is
/// not one.
const AUDIT_PREFIX: &str = "sensitive read:";

struct Rotating {
    path: PathBuf,
    file: File,
    size: u64,
    limit: u64,
}

impl Rotating {
    fn open(path: &Path, limit: u64) -> std::io::Result<Self> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        let file = Self::append(path)?;
        let size = file.metadata()?.len();
        Ok(Self {
            path: path.to_path_buf(),
            file,
            size,
            limit,
        })
    }

    fn append(path: &Path) -> std::io::Result<File> {
        OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)
    }

    fn numbered(&self, n: usize) -> PathBuf {
        let mut name = self.path.clone().into_os_string();
        name.push(format!(".{n}"));
        PathBuf::from(name)
    }

    fn rotate(&mut self) -> std::io::Result<()> {
        let _ = std::fs::remove_file(self.numbered(KEEP - 1));
        for n in (1..KEEP - 1).rev() {
            let _ = std::fs::rename(self.numbered(n), self.numbered(n + 1));
        }
        std::fs::rename(&self.path, self.numbered(1))?;
        self.file = Self::append(&self.path)?;
        self.size = 0;
        Ok(())
    }

    fn write_line(&mut self, line: &str) {
        let needed = line.len() as u64 + 1;
        if self.size > 0 && self.size + needed > self.limit {
            let _ = self.rotate();
        }
        if writeln!(self.file, "{line}").is_ok() {
            self.size += needed;
        }
    }
}

/// The daemon's log: a [`Logger`] (level and format) and its destination.
pub struct ServiceLog {
    logger: Logger,
    file: Option<Mutex<Rotating>>,
}

impl ServiceLog {
    /// `file` is `[log] file`; `None` writes to stderr. A file that cannot be
    /// opened is an error here, before the daemon starts.
    pub fn open(logger: Logger, file: Option<&Path>) -> std::io::Result<Self> {
        Self::open_with_limit(logger, file, ROTATE_AT)
    }

    pub fn open_with_limit(
        logger: Logger,
        file: Option<&Path>,
        limit: u64,
    ) -> std::io::Result<Self> {
        let file = match file {
            Some(path) => Some(Mutex::new(Rotating::open(path, limit)?)),
            None => None,
        };
        Ok(Self { logger, file })
    }

    /// One message at `now_ms`; the level is `info`, or above every filter
    /// for an audit line.
    pub fn write(&self, now_ms: u64, message: &str) {
        let level = if message.starts_with(AUDIT_PREFIX) {
            Level::Error
        } else {
            Level::Info
        };
        let Some(line) = self.logger.line(level, now_ms, message) else {
            return;
        };
        match &self.file {
            Some(file) => file
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .write_line(&line),
            None => {
                let _ = writeln!(std::io::stderr(), "{line}");
            }
        }
    }

    pub fn log(&self, message: &str) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64);
        self.write(now, message);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::LogFormat;

    struct Dir(PathBuf);
    impl Dir {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!("ant-slog-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn log_in(dir: &Path, level: Level, limit: u64) -> (ServiceLog, PathBuf) {
        let path = dir.join("logs").join("daemon.log");
        let logger = Logger {
            level,
            format: LogFormat::Text,
        };
        (
            ServiceLog::open_with_limit(logger, Some(&path), limit).unwrap(),
            path,
        )
    }

    #[test]
    fn lines_go_to_the_file_with_mode_0600() {
        let dir = Dir::new("mode");
        let (log, path) = log_in(dir.path(), Level::Info, ROTATE_AT);
        log.write(0, "daemon ready");
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("INFO") && text.contains("daemon ready"));
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn a_level_above_info_drops_the_chatter_but_never_an_audit_line() {
        let dir = Dir::new("level");
        let (log, path) = log_in(dir.path(), Level::Error, ROTATE_AT);
        log.write(0, "daemon ready");
        log.write(0, "sensitive read: caller=local:1 op=x run=a size=1");
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains("daemon ready"));
        assert!(text.contains("sensitive read: caller=local:1"));
    }

    #[test]
    fn the_file_rotates_and_keeps_five() {
        let dir = Dir::new("rotate");
        let (log, path) = log_in(dir.path(), Level::Info, 200);
        for n in 0..60 {
            log.write(0, &format!("line number {n:04} with some padding text"));
        }
        let parent = path.parent().unwrap();
        let names: Vec<String> = std::fs::read_dir(parent)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names.len(), KEEP, "{names:?}");
        assert!(!names.iter().any(|n| n.ends_with(".5")));
        let newest = std::fs::read_to_string(&path).unwrap();
        assert!(newest.contains("0059"));
    }

    #[test]
    fn an_unwritable_file_is_an_error_at_open() {
        let logger = Logger {
            level: Level::Info,
            format: LogFormat::Text,
        };
        assert!(ServiceLog::open(logger, Some(Path::new("/proc/nope/daemon.log"))).is_err());
    }
}
