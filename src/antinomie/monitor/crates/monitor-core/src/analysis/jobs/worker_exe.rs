// SPDX-License-Identifier: MIT
//! The executable sandboxed workers run: this program, even after a rebuild
//! replaced it on disk.
use super::*;
use std::os::unix::fs::MetadataExt;
use std::sync::OnceLock;

const COPY_PREFIX: &str = "antinomie-worker-exe-";

/// The running program's path, or a private copy of it when the file at that
/// path was removed or replaced (a rebuild while the app runs). The kernel
/// then reports the path with " (deleted)", nothing exists there to mount or
/// run, and a new binary at the old path would not match this process. The
/// copy is taken once from `/proc/self/exe`, which still names the running
/// image.
pub(crate) fn worker_executable() -> Result<PathBuf, String> {
    let current = std::env::current_exe().map_err(|error| error.to_string())?;
    if !replaced(&current) {
        return Ok(current);
    }
    static COPY: OnceLock<Result<PathBuf, String>> = OnceLock::new();
    COPY.get_or_init(|| copy_running(&std::env::temp_dir()))
        .clone()
}

fn replaced(path: &Path) -> bool {
    path.to_string_lossy().ends_with(" (deleted)") || !path.is_file()
}

fn copy_running(root: &Path) -> Result<PathBuf, String> {
    remove_stale_copies(root);
    let directory = root.join(format!("{COPY_PREFIX}{}", std::process::id()));
    storage::private_dir(&directory).map_err(|error| error.to_string())?;
    let copy = directory.join("antinomie-monitor");
    fs::copy("/proc/self/exe", &copy)
        .map_err(|error| format!("copying the running program for workers: {error}"))?;
    fs::set_permissions(&copy, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
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
}
