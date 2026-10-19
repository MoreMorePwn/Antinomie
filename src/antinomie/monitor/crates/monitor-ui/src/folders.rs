//! Host folder selection without blocking native rendering.
use std::{
    io::Read,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::mpsc::{self, Receiver},
    thread::{self, JoinHandle},
};

#[derive(Clone, Copy)]
pub(crate) enum Kind {
    Disk,
    Recording,
    BaseImport,
    UploadFile,
    ExplorerRoot,
}

#[derive(Clone, Copy)]
pub(crate) struct Target {
    pub(crate) generation: u64,
    pub(crate) kind: Kind,
}

pub(crate) struct FolderPicker {
    child: Option<Child>,
    target: Option<Target>,
    program: Option<PathBuf>,
    probe: Option<(Receiver<Option<PathBuf>>, JoinHandle<()>)>,
}

impl FolderPicker {
    pub(crate) fn new() -> Self {
        Self {
            child: None,
            target: None,
            program: None,
            probe: None,
        }
    }

    pub(crate) fn available(&self) -> bool {
        self.child.is_none() && self.installed()
    }

    pub(crate) fn installed(&self) -> bool {
        self.program.is_some()
    }

    pub(crate) fn checking(&self) -> bool {
        self.probe.is_some()
    }

    pub(crate) fn pending(&self) -> bool {
        self.child.is_some() || self.checking()
    }

    /// Recheck explicitly; rendering only reads the cached result.
    pub(crate) fn refresh(&mut self, ctx: &eframe::egui::Context) {
        let paths = std::env::var_os("PATH");
        self.start_probe(ctx.clone(), move || {
            paths.and_then(|paths| {
                std::env::split_paths(&paths)
                    .map(|directory| directory.join("zenity"))
                    .find(|path| path.is_file())
            })
        });
    }

    fn start_probe(
        &mut self,
        ctx: eframe::egui::Context,
        find: impl FnOnce() -> Option<PathBuf> + Send + 'static,
    ) {
        if self.probe.is_some() {
            return;
        }
        let (sender, receiver) = mpsc::sync_channel(1);
        match thread::Builder::new()
            .name("file-chooser-check".into())
            .spawn(move || {
                let _ = sender.send(find());
                ctx.request_repaint_of(eframe::egui::ViewportId::ROOT);
            }) {
            Ok(thread) => self.probe = Some((receiver, thread)),
            Err(error) => eprintln!("file chooser check: {error}"),
        }
    }

    pub(crate) fn choose(&mut self, target: Target) -> Result<(), String> {
        if self.child.is_some() {
            return Err("folder selection is already open".into());
        }
        let arguments: &[&str] = if matches!(target.kind, Kind::UploadFile) {
            &["--file-selection", "--title=Choose file to upload"]
        } else {
            &[
                "--file-selection",
                "--directory",
                "--title=Choose host folder",
            ]
        };
        let program = self.program.as_ref().ok_or("File chooser unavailable; use Tools > App dependencies > Check again, or enter the path manually")?;
        let child = Command::new(program)
            .args(arguments)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| error.to_string())?;
        self.child = Some(child);
        self.target = Some(target);
        Ok(())
    }

    pub(crate) fn poll(&mut self) -> Option<(Target, Result<Option<PathBuf>, String>)> {
        if let Some((receiver, _)) = &self.probe {
            match receiver.try_recv() {
                Ok(program) => {
                    self.program = program;
                    // The worker has sent its result; do not wait on a filesystem probe.
                    self.probe.take();
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.probe.take();
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
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

/// Open `directory` in the desktop file manager and wait for the request.
///
/// The FileManager1 D-Bus service reaches the file manager itself. `xdg-open`
/// is only the fallback: it hands a folder to whichever application claims
/// `inode/directory`, which on Xfce can be the Catfish search tool.
pub(crate) fn show(directory: &Path) -> Result<(), String> {
    let shown = Command::new("dbus-send")
        .args([
            "--session",
            "--print-reply",
            "--reply-timeout=5000",
            "--dest=org.freedesktop.FileManager1",
            "/org/freedesktop/FileManager1",
            "org.freedesktop.FileManager1.ShowFolders",
        ])
        .arg(format!("array:string:{}", file_uri(directory)))
        .arg("string:")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if shown.is_ok_and(|status| status.success()) {
        return Ok(());
    }
    let status = Command::new("xdg-open")
        .arg(directory)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| format!("Open directory: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("Open directory failed: {status}"))
    }
}

/// `show` on a background thread; a failure is only logged.
pub(crate) fn show_detached(directory: PathBuf) {
    thread::spawn(move || {
        if let Err(error) = show(&directory) {
            eprintln!("{error}");
        }
    });
}

/// Hand an existing file to the desktop's default application on a background
/// thread; a failure is only logged. This app opens nothing for writing: what
/// the other application does with the file is its own business.
pub(crate) fn open_file_detached(file: PathBuf) {
    thread::spawn(move || {
        let status = Command::new("xdg-open")
            .arg(&file)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        match status {
            Ok(status) if status.success() => {}
            Ok(status) => eprintln!("Open file failed: {status}"),
            Err(error) => eprintln!("Open file: {error}"),
        }
    });
}

/// A `file://` URI with every byte outside the unreserved set and `/`
/// percent-encoded, so a comma cannot split the dbus-send array argument.
fn file_uri(path: &Path) -> String {
    use std::os::unix::ffi::OsStrExt;
    let mut uri = String::from("file://");
    for &byte in path.as_os_str().as_bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~/".contains(&byte) {
            uri.push(byte as char);
        } else {
            uri.push_str(&format!("%{byte:02X}"));
        }
    }
    uri
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
    fn a_folder_uri_escapes_separators_of_the_dbus_array() {
        let uri = super::file_uri(std::path::Path::new("/tmp/a b,c/ü%"));
        assert_eq!(uri, "file:///tmp/a%20b%2Cc/%C3%BC%25");
    }

    #[test]
    fn availability_does_not_wait_for_a_slow_probe_and_can_be_refreshed() {
        let ctx = eframe::egui::Context::default();
        let mut picker = super::FolderPicker::new();
        let (release, blocked) = std::sync::mpsc::channel();
        picker.start_probe(ctx.clone(), move || {
            blocked.recv().unwrap();
            Some("/test/zenity".into())
        });
        for _ in 0..1000 {
            assert!(!picker.available());
            assert!(!picker.installed());
            picker.poll();
        }
        assert!(picker.checking());
        release.send(()).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while picker.checking() {
            picker.poll();
            assert!(std::time::Instant::now() < deadline);
            std::thread::yield_now();
        }
        assert!(picker.available());
        picker.start_probe(ctx, || None);
        while picker.checking() {
            picker.poll();
            assert!(std::time::Instant::now() < deadline);
            std::thread::yield_now();
        }
        assert!(!picker.available());
    }
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
