// SPDX-License-Identifier: GPL-3.0-only
//! The private account file the shared sandbox profile binds over
//! `/etc/passwd`: one unprivileged name, no host account.
use std::{
    ffi::OsString,
    fs,
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Command,
};

/// Address space of a sandboxed `qemu-img` (the analysis workers' figure).
const QEMU_IMG_ADDRESS_SPACE: u64 = 8 * 1024 * 1024 * 1024;
/// Files a sandboxed `qemu-img` may open.
const QEMU_IMG_FILES: u32 = 64;
/// Size of its `/tmp`.
const QEMU_IMG_TMP: u64 = 64 * 1024 * 1024;

/// A private folder (mode 0700, under the system temp folder) holding a
/// one-line `passwd`. Removed when dropped.
pub(crate) struct Account {
    folder: PathBuf,
    passwd: PathBuf,
}

impl Account {
    pub(crate) fn new() -> Result<Self, String> {
        let folder = std::env::temp_dir().join(format!(
            "antinomie-disk-sandbox-{}-{}",
            std::process::id(),
            crate::storage::unique_id()
        ));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&folder)
            .map_err(|error| format!("{}: {error}", folder.display()))?;
        let passwd = folder.join("passwd");
        let written = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&passwd)
            .and_then(|mut file| file.write_all(b"nobody:x:65534:65534::/tmp:/bin/false\n"));
        if let Err(error) = written {
            let _ = fs::remove_dir_all(&folder);
            return Err(format!("{}: {error}", passwd.display()));
        }
        Ok(Self { folder, passwd })
    }

    /// The file to bind over `/etc/passwd`.
    pub(crate) fn passwd(&self) -> &Path {
        &self.passwd
    }
}

impl Drop for Account {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.folder);
    }
}

/// `qemu-img` as the sandbox sees it: it must live under `/usr`, the only
/// part of the host the sandbox shows.
pub(crate) fn sandboxed_qemu_img(qemu_img: &Path) -> Result<PathBuf, String> {
    let found = crate::dependencies::executable(qemu_img)
        .ok_or_else(|| format!("{} was not found", qemu_img.display()))?;
    let real = fs::canonicalize(&found).unwrap_or(found);
    if real.starts_with("/usr") {
        Ok(real)
    } else {
        Err(format!(
            "importing a qcow2 image needs qemu-img under /usr (the sandbox shows nothing \
             else of the host); {} is not",
            real.display()
        ))
    }
}

/// A `qemu-img` command line inside the analysis sandbox: no network, no
/// host files but `input` (read-only, at `/input`, when given) and the one
/// writable folder `out` (at `/out`, the working directory), a bounded
/// `/tmp`, no capabilities, under `prlimit`. `arguments` are `qemu-img`'s;
/// they name only `/input` and `/out`.
pub(crate) fn qemu_img_in_sandbox(
    qemu_img: &Path,
    account: &Path,
    input: Option<&Path>,
    out: &Path,
    arguments: &[OsString],
) -> Command {
    let mut command = Command::new("/usr/bin/bwrap");
    crate::sandbox_profile::apply(&mut command, account, &[], QEMU_IMG_TMP);
    if let Some(input) = input {
        command.arg("--ro-bind").arg(input).arg("/input");
    }
    command
        .arg("--bind")
        .arg(out)
        .arg("/out")
        .args([
            "--remount-ro",
            "/",
            "--setenv",
            "LC_ALL",
            "C",
            "--setenv",
            "HOME",
            "/nonexistent",
            "--chdir",
            "/out",
            "--",
            "/usr/bin/prlimit",
        ])
        .arg(format!("--as={QEMU_IMG_ADDRESS_SPACE}"))
        .arg(format!("--nofile={QEMU_IMG_FILES}"))
        .args(["--core=0", "--"])
        .arg(qemu_img)
        .args(arguments);
    command.env_clear();
    command
}
