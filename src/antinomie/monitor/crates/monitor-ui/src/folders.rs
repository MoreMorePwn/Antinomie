//! Host folder selection without blocking native rendering.
use std::{
    io::Read,
    path::PathBuf,
    process::{Child, Command, Stdio},
};

#[derive(Clone, Copy)]
pub(crate) enum Kind {
    Disk,
    Recording,
    BaseImport,
    UploadRoot,
}

#[derive(Clone, Copy)]
pub(crate) struct Target {
    pub(crate) generation: u64,
    pub(crate) kind: Kind,
}

pub(crate) struct FolderPicker {
    child: Option<Child>,
    target: Option<Target>,
}

impl FolderPicker {
    pub(crate) fn new() -> Self {
        Self {
            child: None,
            target: None,
        }
    }

    pub(crate) fn available(&self) -> bool {
        self.child.is_none() && Self::installed()
    }

    pub(crate) fn installed() -> bool {
        std::env::var_os("PATH").is_some_and(|paths| {
            std::env::split_paths(&paths).any(|directory| directory.join("zenity").is_file())
        })
    }

    pub(crate) fn choose(&mut self, target: Target) -> Result<(), String> {
        if self.child.is_some() {
            return Err("folder selection is already open".into());
        }
        let child = Command::new("zenity")
            .args([
                "--file-selection",
                "--directory",
                "--title=Choose host folder",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| error.to_string())?;
        self.child = Some(child);
        self.target = Some(target);
        Ok(())
    }

    pub(crate) fn poll(&mut self) -> Option<(Target, Result<Option<PathBuf>, String>)> {
        let child = self.child.as_mut()?;
        let status = match child.try_wait() {
            Ok(Some(status)) => Ok(status),
            Ok(None) => return None,
            Err(error) => Err(error.to_string()),
        };
        let target = self.target.take()?;
        let mut child = self.child.take()?;
        if status.is_err() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let result = status.and_then(|status| {
            if status.success() {
                let mut data = Vec::new();
                child
                    .stdout
                    .take()
                    .ok_or("folder picker stdout unavailable")?
                    .take(8193)
                    .read_to_end(&mut data)
                    .map_err(|error| error.to_string())?;
                if data.len() > 8192 {
                    return Err("folder picker path exceeds the supported length".into());
                }
                let selected = String::from_utf8(data).map_err(|error| error.to_string())?;
                let path = selected.strip_suffix('\n').unwrap_or(&selected);
                Ok((!path.is_empty()).then(|| PathBuf::from(path)))
            } else if status.code() == Some(1) {
                Ok(None)
            } else {
                Err(format!("folder picker failed: {status}"))
            }
        });
        Some((target, result))
    }
}

impl Drop for FolderPicker {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            if let Err(error) = child.kill() {
                eprintln!("folder picker cancellation: {error}");
            }
            if let Err(error) = child.wait() {
                eprintln!("folder picker cleanup: {error}");
            }
        }
    }
}

/// A path the user typed: surrounding spaces removed and a leading `~`
/// expanded to the home directory, as a shell would.
pub(crate) fn user_path(text: &str) -> PathBuf {
    let text = text.trim();
    let home = || std::env::var_os("HOME").map(PathBuf::from);
    if text == "~" {
        if let Some(home) = home() {
            return home;
        }
    } else if let Some(rest) = text.strip_prefix("~/") {
        if let Some(home) = home() {
            return home.join(rest);
        }
    }
    PathBuf::from(text)
}

#[cfg(test)]
mod path_tests {
    #[test]
    fn typed_paths_expand_the_home_directory() {
        let home = std::path::PathBuf::from(std::env::var_os("HOME").unwrap());
        assert_eq!(super::user_path(" ~/bases/x "), home.join("bases/x"));
        assert_eq!(super::user_path("~"), home);
        assert_eq!(
            super::user_path("/abs/~x"),
            std::path::PathBuf::from("/abs/~x")
        );
        assert_eq!(
            super::user_path("~other/x"),
            std::path::PathBuf::from("~other/x")
        );
    }
}
