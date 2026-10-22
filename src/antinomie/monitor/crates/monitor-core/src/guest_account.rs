// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
use crate::api::{GuestCredentials, validate_guest_username};
use crate::storage;
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const HASH_TIMEOUT: Duration = Duration::from_secs(15);
const PROVISION_TIMEOUT: Duration = Duration::from_secs(180);

#[cfg(test)]
thread_local! {
    static FAIL_PROVISION: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
#[cfg(test)]
pub(crate) fn fail_next_provision() {
    FAIL_PROVISION.with(|fail| fail.set(true));
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct GuestAccount {
    username: String,
    password_hash: String,
}
impl std::fmt::Debug for GuestAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuestAccount")
            .field("username", &self.username)
            .field("password_hash", &"[REDACTED]")
            .finish()
    }
}
impl GuestAccount {
    pub(crate) fn from_credentials(credentials: GuestCredentials) -> Result<Self, String> {
        Self::hash_with(credentials, Path::new("openssl"))
    }
    fn hash_with(credentials: GuestCredentials, executable: &Path) -> Result<Self, String> {
        let mut command = Command::new(executable);
        command.args(["passwd", "-6", "-stdin"]);
        let hash = run_private(command, credentials.password.as_bytes(), true)?;
        let password_hash = String::from_utf8(hash)
            .map_err(|_| "invalid password hash output")?
            .trim_end()
            .to_owned();
        let account = Self {
            username: credentials.username,
            password_hash,
        };
        account.validate()?;
        Ok(account)
    }
    fn validate(&self) -> Result<(), String> {
        validate_guest_username(&self.username)?;
        let parts: Vec<_> = self.password_hash.split('$').collect();
        if parts.len() != 4
            || !parts[0].is_empty()
            || parts[1] != "6"
            || parts[2].is_empty()
            || parts[2].len() > 16
            || parts[3].len() != 86
            || !parts[2..].iter().all(|part| {
                part.bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'.' || c == b'/')
            })
        {
            return Err("invalid salted SHA-512 password hash".into());
        }
        Ok(())
    }
    /// The account's name (uid and gid 1000 in the guest).
    pub(crate) fn username(&self) -> &str {
        &self.username
    }
    pub(crate) fn save(&self, directory: &Path) -> Result<(), String> {
        self.validate()?;
        storage::atomic_json(&directory.join("guest-account.json"), self)
    }
    pub(crate) fn load(directory: &Path) -> Result<Self, String> {
        let path = directory.join("guest-account.json");
        let metadata = fs::symlink_metadata(&path)
            .map_err(|_| "guest account provisioning record is unavailable")?;
        let owner = fs::metadata(directory)
            .map_err(|_| "guest account directory is unavailable")?
            .uid();
        if !metadata.is_file()
            || metadata.permissions().mode() & 0o777 != 0o600
            || metadata.uid() != owner
            || metadata.len() > 4096
        {
            return Err(
                "guest account provisioning record must be an owned private regular file".into(),
            );
        }
        // Never surface serde errors: malformed sensitive fields could appear in them.
        let account: Self =
            storage::read_json(&path).map_err(|_| "invalid guest account provisioning record")?;
        account.validate()?;
        Ok(account)
    }
    pub(crate) fn provision(&self, disk: &Path) -> Result<(), String> {
        #[cfg(test)]
        if FAIL_PROVISION.with(|fail| fail.replace(false)) {
            return Err("injected offline provisioning failure".into());
        }
        let executable =
            crate::dependencies::require_tool(Path::new("virt-customize"), "libguestfs-tools")?;
        self.provision_with(disk, &executable)
    }
    fn provision_with(&self, disk: &Path, executable: &Path) -> Result<(), String> {
        self.validate()?;
        let username = &self.username;
        let hash = &self.password_hash;
        let staging = format!("/root/.antinomie-account-{}", storage::unique_id());
        // The libguestfs write operation keeps the hash out of guest shell argv too.
        let script = format!(
            "mkdir {staging}\nchmod 0700:{staging}\nwrite {staging}/password:{username}:{hash}\nchmod 0600:{staging}/password\nrun-command set -eu; trap 'rm -rf {staging}' EXIT; if getent passwd 1000 >/dev/null || getent group 1000 >/dev/null || getent passwd '{username}' >/dev/null || getent group '{username}' >/dev/null; then exit 1; fi; groupadd -g 1000 '{username}'; useradd -u 1000 -g 1000 -m -s /bin/bash '{username}'; usermod -a -G sudo '{username}'; chpasswd -e < {staging}/password; passwd -l root >/dev/null; printf '%s\\n' '{username} ALL=(ALL:ALL) ALL' > /etc/sudoers.d/antinomie-account; chmod 0440 /etc/sudoers.d/antinomie-account; visudo -cf /etc/sudoers.d/antinomie-account >/dev/null\n"
        );
        let mut command = Command::new(executable);
        command
            .args(["--no-network", "--no-logfile", "--format", "qcow2", "-a"])
            .arg(disk)
            .args(["--commands-from-file", "/dev/stdin"])
            .env("LIBGUESTFS_BACKEND", "direct")
            .env("LIBGUESTFS_DEBUG", "0")
            .env("LIBGUESTFS_TRACE", "0");
        run_private(command, script.as_bytes(), false)?;
        File::open(disk)
            .and_then(|file| file.sync_all())
            .map_err(|_| "cannot sync provisioned disk".to_owned())
    }
}

fn run_private(mut command: Command, input: &[u8], capture_hash: bool) -> Result<Vec<u8>, String> {
    let timeout = if capture_hash {
        HASH_TIMEOUT
    } else {
        PROVISION_TIMEOUT
    };
    run_private_with_timeout(&mut command, input, capture_hash, timeout)
}

fn terminate_owned_group(child: &mut Child) -> Result<(), String> {
    let group = format!("-{}", child.id());
    let group_killed = Command::new("/bin/kill")
        .args(["--signal", "KILL", "--", &group])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    if !group_killed && child.try_wait().ok().flatten().is_none() {
        child
            .kill()
            .map_err(|_| "offline credential tool cleanup failed")?;
    }
    child
        .wait()
        .map_err(|_| "offline credential tool cleanup failed")?;
    Ok(())
}

fn run_private_with_timeout(
    command: &mut Command,
    input: &[u8],
    capture_hash: bool,
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    // This fits a fresh Linux pipe even if the tool never reads its stdin.
    if input.len() > 4096 {
        return Err("offline credential tool input exceeds limit".into());
    }
    let deadline = Instant::now() + timeout;
    let mut captured_stdout = if capture_hash {
        let (reader, writer) =
            UnixStream::pair().map_err(|_| "password hash output channel failed")?;
        reader
            .set_nonblocking(true)
            .map_err(|_| "password hash output channel failed")?;
        command.stdout(Stdio::from(OwnedFd::from(writer)));
        Some(reader)
    } else {
        command.stdout(Stdio::null());
        None
    };
    command
        .process_group(0)
        .stdin(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = command
        .spawn()
        .map_err(|_| "offline credential tool could not be started")?;
    // Drop the parent's configured writer so EOF reflects owned child writers.
    command.stdout(Stdio::null());
    let write_result = child
        .stdin
        .take()
        .ok_or("offline credential tool input is unavailable")
        .and_then(|mut stdin| {
            stdin
                .write_all(input)
                .map_err(|_| "offline credential tool input failed")
        });
    let result = (|| -> Result<Vec<u8>, String> {
        write_result?;
        let mut output = Vec::new();
        let mut output_complete = !capture_hash;
        let mut status = None;
        loop {
            if let Some(reader) = captured_stdout.as_mut().filter(|_| !output_complete) {
                let mut chunk = [0; 512];
                loop {
                    let capacity = chunk.len().min(4097 - output.len());
                    match reader.read(&mut chunk[..capacity]) {
                        Ok(0) => {
                            output_complete = true;
                            break;
                        }
                        Ok(len) => {
                            output.extend_from_slice(&chunk[..len]);
                            if output.len() > 4096 {
                                return Err("password hash output exceeded limit".into());
                            }
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(_) => return Err("password hash output failed".into()),
                    }
                }
            }
            if status.is_none() {
                status = child
                    .try_wait()
                    .map_err(|_| "offline credential tool wait failed")?;
            }
            if let Some(status) = status {
                if !status.success() {
                    return Err("offline credential provisioning failed; unpublished disk retained for cleanup".into());
                }
                if output_complete {
                    return Ok(output);
                }
            }
            if Instant::now() >= deadline {
                return Err(
                    "offline credential tool timed out; unpublished disk retained for cleanup"
                        .into(),
                );
            }
            thread::sleep(Duration::from_millis(10));
        }
    })();
    if result.is_err() {
        terminate_owned_group(&mut child)?;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tool_deadline_reaps_owned_child_and_preserves_unrelated_process() {
        let root =
            std::env::temp_dir().join(format!("ant-account-timeout-{}", storage::unique_id()));
        storage::private_dir(&root).unwrap();
        let tool = root.join("hung-tool");
        fs::write(
            &tool,
            "#!/bin/sh\nroot=$(dirname \"$0\")\nprintf '%s\\n' \"$$\" > \"$root/tool-pid\"\ncat >/dev/null\nsleep 60 &\nprintf '%s\\n' \"$!\" > \"$root/descendant-pid\"\nif test \"$1\" = exit-parent; then exit 0; fi\nwait\n",
        )
        .unwrap();
        fs::set_permissions(&tool, fs::Permissions::from_mode(0o700)).unwrap();
        let mut unrelated = Command::new("sleep").arg("60").spawn().unwrap();
        let secret = "private-timeout-password";
        for (capture_hash, exit_parent) in [(false, false), (true, false), (true, true)] {
            let started = Instant::now();
            let mut command = Command::new(&tool);
            if exit_parent {
                command.arg("exit-parent");
            }
            let error = run_private_with_timeout(
                &mut command,
                secret.as_bytes(),
                capture_hash,
                Duration::from_millis(150),
            )
            .unwrap_err();
            assert!(error.contains("timed out"));
            assert!(!error.contains(secret));
            assert!(started.elapsed() < Duration::from_secs(3));
            let pid = fs::read_to_string(root.join("tool-pid")).unwrap();
            assert!(!Path::new("/proc").join(pid.trim()).exists());
            let descendant = fs::read_to_string(root.join("descendant-pid")).unwrap();
            let stopped_deadline = Instant::now() + Duration::from_secs(1);
            while let Ok(stat) =
                fs::read_to_string(Path::new("/proc").join(descendant.trim()).join("stat"))
            {
                if stat.split_once(") ").unwrap().1.starts_with('Z') {
                    break;
                }
                assert!(Instant::now() < stopped_deadline);
                thread::sleep(Duration::from_millis(10));
            }
            assert!(unrelated.try_wait().unwrap().is_none());
        }
        unrelated.kill().unwrap();
        unrelated.wait().unwrap();
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn oversized_tool_input_and_output_are_rejected_without_exposing_content() {
        let error = run_private_with_timeout(
            &mut Command::new("missing-tool"),
            &[0; 4097],
            true,
            Duration::from_millis(100),
        )
        .unwrap_err();
        assert!(error.contains("input exceeds limit"));
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "cat >/dev/null; head -c 8192 /dev/zero"]);
        let error = run_private_with_timeout(
            &mut command,
            b"private-output-password",
            true,
            Duration::from_secs(1),
        )
        .unwrap_err();
        assert!(error.contains("output exceeded limit"));
        assert!(!error.contains("private-output-password"));
    }
    fn account() -> GuestAccount {
        GuestAccount {
            username: "analyst".into(),
            password_hash: format!("$6$fixturesalt${}", "a".repeat(86)),
        }
    }
    fn fake_tool(directory: &Path, fail: bool) -> std::path::PathBuf {
        let path = directory.join("fake-tool");
        fs::write(&path, format!("#!/bin/sh\nroot=$(dirname \"$0\")\nprintf '%s\\n' \"$@\" > \"$root/argv\"\ncat > \"$root/input\"\ncat \"$root/input\" >&2\nexit {}\n", if fail { 1 } else { 0 })).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }
    #[test]
    fn offline_tool_uses_stdin_and_never_exposes_sensitive_output() {
        let root = std::env::temp_dir().join(format!("ant-account-{}", storage::unique_id()));
        storage::private_dir(&root).unwrap();
        let disk = root.join("disk.qcow2");
        fs::write(&disk, b"unchanged disk fixture").unwrap();
        let account = account();
        account
            .provision_with(&disk, &fake_tool(&root, false))
            .unwrap();
        let argv = fs::read_to_string(root.join("argv")).unwrap();
        assert!(argv.contains("--no-network\n--no-logfile"));
        assert!(argv.contains("/dev/stdin"));
        assert!(!argv.contains(&account.password_hash));
        assert!(!argv.contains(&account.username));
        let input = fs::read_to_string(root.join("input")).unwrap();
        assert!(input.contains(&account.password_hash));
        let shell_command = input
            .lines()
            .find(|line| line.starts_with("run-command "))
            .unwrap();
        assert!(!shell_command.contains(&account.password_hash));
        assert!(input.contains("groupadd -g 1000"));
        assert!(input.contains("useradd -u 1000 -g 1000"));
        assert!(!input.contains("NOPASSWD"));
        let error = account
            .provision_with(&disk, &fake_tool(&root, true))
            .unwrap_err();
        assert!(!error.contains(&account.password_hash));
        assert!(!format!("{account:?}").contains(&account.password_hash));
        assert!(
            account
                .provision_with(&disk, &root.join("missing"))
                .is_err()
        );
        assert_eq!(fs::read(&disk).unwrap(), b"unchanged disk fixture");
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn account_record_is_private_and_malformed_hashes_are_redacted() {
        let root =
            std::env::temp_dir().join(format!("ant-account-record-{}", storage::unique_id()));
        storage::private_dir(&root).unwrap();
        let account = account();
        account.save(&root).unwrap();
        assert_eq!(
            fs::metadata(root.join("guest-account.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            GuestAccount::load(&root).unwrap().password_hash,
            account.password_hash
        );
        fs::set_permissions(
            root.join("guest-account.json"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(GuestAccount::load(&root).is_err());
        fs::set_permissions(
            root.join("guest-account.json"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        fs::write(
            root.join("guest-account.json"),
            br#"{"username":"analyst","password_hash":123456789}"#,
        )
        .unwrap();
        assert!(!GuestAccount::load(&root).unwrap_err().contains("123456789"));
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn openssl_preserves_all_128_password_bytes_and_randomizes_salt() {
        let mut command = Command::new("openssl");
        command.args(["passwd", "-6", "-stdin", "-salt", "fixture"]);
        let first = run_private(command, "x".repeat(128).as_bytes(), true).unwrap();
        let mut command = Command::new("openssl");
        command.args(["passwd", "-6", "-stdin", "-salt", "fixture"]);
        let second =
            run_private(command, format!("{}y", "x".repeat(127)).as_bytes(), true).unwrap();
        assert_ne!(first, second);
        let credentials = GuestCredentials::new("analyst".into(), "x".repeat(128)).unwrap();
        let first = GuestAccount::from_credentials(credentials.clone()).unwrap();
        let second = GuestAccount::from_credentials(credentials).unwrap();
        assert_ne!(first.password_hash, second.password_hash);
    }
}
