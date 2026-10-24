// SPDX-License-Identifier: GPL-3.0-only
//! The one account a sandboxed tool is told about: the host user's name and
//! ids, written to a private passwd file that is bound read-only into the
//! sandbox.
use super::*;

/// Resolve only the actual host UID's local account, never an inherited USER.
/// This bounded lookup is for background analysis/export work, not rendering.
pub(crate) fn host_user_name() -> Result<String, String> {
    const ACCOUNT_DATABASE_MAX_SIZE: u64 = 1024 * 1024;
    let mut encoded = Vec::new();
    File::open("/etc/passwd")
        .and_then(|file| {
            file.take(ACCOUNT_DATABASE_MAX_SIZE + 1)
                .read_to_end(&mut encoded)
        })
        .map_err(|error| format!("analysis account lookup unavailable: {error}"))?;
    if encoded.len() as u64 > ACCOUNT_DATABASE_MAX_SIZE {
        return Err("analysis account lookup exceeded 1 MiB bound".into());
    }
    let uid = rustix::process::getuid().as_raw();
    let mut matched = None;
    for line in encoded.split(|byte| *byte == b'\n') {
        let mut fields = line.split(|byte| *byte == b':');
        let name = fields.next().unwrap_or_default();
        let _password = fields.next();
        let candidate = fields
            .next()
            .and_then(|value| std::str::from_utf8(value).ok())
            .and_then(|value| value.parse::<u32>().ok());
        if candidate != Some(uid) {
            continue;
        }
        if matched.is_some() {
            return Err("analysis account lookup is ambiguous for current UID".into());
        }
        if name.is_empty()
            || name.len() > 64
            || !name
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(byte))
        {
            return Err("analysis account has an unsupported user name; Ghidra ownership cannot be established".into());
        }
        matched = Some(String::from_utf8(name.to_vec()).map_err(|error| error.to_string())?);
    }
    matched.ok_or_else(|| {
        "current UID has no local account; Ghidra ownership cannot be established".into()
    })
}

pub(super) fn sandbox_passwd(directory: &Path) -> Result<PathBuf, String> {
    let name = host_user_name()?;
    let uid = rustix::process::getuid().as_raw();
    let gid = rustix::process::getgid().as_raw();
    let path = directory.join(format!("sandbox-account-{}.passwd", storage::unique_id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|error| format!("sandbox account mapping: {error}"))?;
    // Only one name/UID/GID crosses the boundary. No host home, shell, password,
    // GECOS, or other account is exposed. JVM settings stay in bounded tmpfs.
    writeln!(file, "{name}:x:{uid}:{gid}::/tmp:/bin/false")
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("sandbox account mapping: {error}"))?;
    Ok(path)
}
