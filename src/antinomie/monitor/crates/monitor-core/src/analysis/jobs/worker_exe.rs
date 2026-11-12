// SPDX-License-Identifier: GPL-3.0-only
//! The executable sandboxed workers run: this program, even after a rebuild
//! replaced it on disk.
use super::*;
use std::os::unix::fs::MetadataExt;
use std::sync::{Mutex, Once};

const COPY_PREFIX: &str = "antinomie-worker-exe-";

/// The running program's path, or a private copy of it when the file at that
/// path was removed or replaced (a rebuild while the app runs). The kernel
/// then reports the path with " (deleted)", nothing exists there to mount or
/// run, and a new binary at the old path would not match this process. The
/// copy is taken from `/proc/self/exe`, which still names the running image,
/// once it worked; a copy that failed (a full `/tmp`) is tried again at the
/// next call, so one failure does not stop every later worker (BH-24). The
/// first call removes the copies of processes that have exited, whatever
/// this process's own binary is.
pub(crate) fn worker_executable() -> Result<PathBuf, String> {
    sweep_stale_copies();
    let current = std::env::current_exe().map_err(|error| error.to_string())?;
    if !replaced(&current) {
        return Ok(current);
    }
    static COPY: Mutex<Option<PathBuf>> = Mutex::new(None);
    let mut copy = COPY.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(path) = copy.as_ref().filter(|path| path.is_file()) {
        return Ok(path.clone());
    }
    let made = copy_running(&std::env::temp_dir())?;
    *copy = Some(made.clone());
    Ok(made)
}

/// Remove the program copies that exited processes left in the temporary
/// folder, once per process.
pub(crate) fn sweep_stale_copies() {
    static SWEPT: Once = Once::new();
    SWEPT.call_once(|| remove_stale_copies(&std::env::temp_dir()));
}

fn replaced(path: &Path) -> bool {
    path.to_string_lossy().ends_with(" (deleted)") || !path.is_file()
}

fn copy_running(root: &Path) -> Result<PathBuf, String> {
    remove_stale_copies(root);
    let directory = root.join(format!("{COPY_PREFIX}{}", std::process::id()));
    storage::private_dir(&directory).map_err(|error| error.to_string())?;
    let copy = directory.join("antinomie-monitor");
    let made = fs::copy("/proc/self/exe", &copy)
        .map_err(|error| format!("copying the running program for workers: {error}"))
        .and_then(|_| {
            fs::set_permissions(&copy, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())
        });
    if let Err(error) = made {
        // A part copy is no use to anyone; the next call starts again.
        let _ = fs::remove_dir_all(&directory);
        return Err(error);
    }
    Ok(copy)
}

/// Copies left by app processes that have exited.
fn remove_stale_copies(root: &Path) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name
            .to_str()
            .and_then(|name| name.strip_prefix(COPY_PREFIX))
            .and_then(|pid| pid.parse::<u32>().ok())
        else {
            continue;
        };
        let owned = entry.metadata().is_ok_and(|metadata| {
            metadata.is_dir() && metadata.uid() == rustix::process::getuid().as_raw()
        });
        if owned && pid != std::process::id() && !Path::new(&format!("/proc/{pid}")).exists() {
            let _ = fs::remove_dir_all(entry.path());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_replaced_program_runs_from_a_private_copy() {
        assert!(replaced(Path::new(
            "/opt/antinomie/antinomie-monitor (deleted)"
        )));
        assert!(replaced(Path::new("/nonexistent/antinomie-monitor")));
        let current = std::env::current_exe().unwrap();
        assert!(!replaced(&current));
        assert_eq!(worker_executable().unwrap(), current);

        let root = std::env::temp_dir().join(format!("ant-worker-exe-{}", storage::unique_id()));
        storage::private_dir(&root).unwrap();
        // A copy left by a process that no longer exists is removed.
        let stale = root.join(format!("{COPY_PREFIX}4294967294"));
        storage::private_dir(&stale).unwrap();
        let copy = copy_running(&root).unwrap();
        assert!(!stale.exists());
        assert_eq!(
            fs::read(&copy).unwrap(),
            fs::read("/proc/self/exe").unwrap()
        );
        assert_eq!(
            fs::metadata(&copy).unwrap().permissions().mode() & 0o777,
            0o700
        );
        fs::remove_dir_all(root).unwrap();
    }

    /// BH-24: a copy that fails leaves nothing behind and is not kept: the
    /// next try works once there is room.
    #[test]
    fn bh_24_a_failed_copy_is_not_kept_and_the_sweep_runs_on_any_binary() {
        let root = std::env::temp_dir().join(format!("ant-worker-exe-{}", storage::unique_id()));
        storage::private_dir(&root).unwrap();
        let mine = root.join(format!("{COPY_PREFIX}{}", std::process::id()));
        // A file where the copy's folder goes: the copy fails.
        fs::write(&mine, b"in the way").unwrap();
        assert!(copy_running(&root).is_err());
        fs::remove_file(&mine).unwrap();
        let copy = copy_running(&root).unwrap();
        assert!(copy.is_file());
        // The process's own binary is not replaced here, and the first call
        // still sweeps (once per process).
        sweep_stale_copies();
        assert_eq!(
            worker_executable().unwrap(),
            std::env::current_exe().unwrap()
        );
        fs::remove_dir_all(root).unwrap();
    }
}
