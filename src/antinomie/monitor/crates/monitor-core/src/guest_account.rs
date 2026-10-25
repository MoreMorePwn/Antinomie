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
/// The groups the Debian installer adds its first user to, where they exist
/// (sudo because root gets no password).
const INSTALLER_GROUPS: &str =
    "cdrom floppy sudo audio dip video plugdev users netdev bluetooth lpadmin scanner";
/// One libguestfs appliance run: the probe, or the provisioning itself
/// (filesystem check, new UUID, directory reindex, account).
const PROVISION_TIMEOUT: Duration = Duration::from_secs(240);

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
    /// The root filesystem UUID provisioning gave this VM's disk: every VM
    /// gets its own, as every installation does. None for disks provisioned
    /// before 0.7.1, which keep their base's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    root_uuid: Option<String>,
}
impl std::fmt::Debug for GuestAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuestAccount")
            .field("username", &self.username)
            .field("password_hash", &"[REDACTED]")
            .field("root_uuid", &self.root_uuid)
            .finish()
    }
}

/// The VM disk as the libguestfs appliance sees it (always `/dev/sda`).
#[derive(Debug, PartialEq, Eq)]
struct DiskLayout {
    /// The root filesystem: the whole disk (`/dev/sda`) or a partition.
    root: String,
}

/// Whether `text` is a lowercase RFC 4122 UUID as `blkid` prints it.
pub(crate) fn valid_uuid(text: &str) -> bool {
    text.len() == 36
        && text.bytes().enumerate().all(|(index, c)| match index {
            8 | 13 | 18 | 23 => c == b'-',
            _ => c.is_ascii_digit() || (b'a'..=b'f').contains(&c),
        })
}

/// A yescrypt salt as crypt(3) makes it: 16 random bytes in crypt's base 64
/// (the 22nd character carries the last two bits).
fn yescrypt_salt() -> Result<String, String> {
    const ALPHABET: &[u8; 64] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut bytes = [0u8; 22];
    File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut bytes))
        .map_err(|_| "cannot read /dev/urandom for the password salt")?;
    Ok(bytes
        .iter()
        .enumerate()
        .map(|(index, byte)| ALPHABET[usize::from(byte & if index < 21 { 63 } else { 3 })] as char)
        .collect())
}

/// A random 128-bit identifier in hex, as /etc/machine-id holds it.
fn random_hex() -> Result<String, String> {
    let mut bytes = [0u8; 16];
    File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut bytes))
        .map_err(|_| "cannot read /dev/urandom for the machine ID")?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// A random (version 4) UUID.
fn random_uuid() -> Result<String, String> {
    let mut bytes = [0u8; 16];
    File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut bytes))
        .map_err(|_| "cannot read /dev/urandom for the VM's filesystem UUID")?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    ))
}

/// A guestfish double-quoted string: backslash escapes for `\`, `"` and
/// control characters (guestfish decodes them before the call).
fn fish_quote(text: &str) -> String {
    let mut quoted = String::with_capacity(text.len() + 2);
    quoted.push('"');
    for c in text.chars() {
        match c {
            '\\' => quoted.push_str("\\\\"),
            '"' => quoted.push_str("\\\""),
            '\n' => quoted.push_str("\\n"),
            '\t' => quoted.push_str("\\t"),
            c if c.is_control() => quoted.push_str(&format!("\\x{:02x}", c as u32)),
            c => quoted.push(c),
        }
    }
    quoted.push('"');
    quoted
}

/// The ext4 root among the probe's `list-filesystems` lines.
fn parse_probe(output: &str) -> Result<DiskLayout, String> {
    let roots: Vec<&str> = output
        .lines()
        .filter_map(|line| line.split_once(": "))
        .filter(|(_, kind)| kind.trim() == "ext4")
        .map(|(device, _)| device.trim())
        .collect();
    match roots[..] {
        [root]
            if root
                .strip_prefix("/dev/sda")
                .is_some_and(|number| number.bytes().all(|c| c.is_ascii_digit())) =>
        {
            Ok(DiskLayout { root: root.into() })
        }
        _ => Err("the VM disk does not hold exactly one ext4 root filesystem".into()),
    }
}

fn guestfish(executable: &Path, disk: &Path, writable: bool) -> Command {
    let mut command = Command::new(executable);
    command
        .arg(if writable { "--rw" } else { "--ro" })
        .args(["--no-progress-bars", "--format=qcow2", "-a"])
        .arg(disk)
        .env("LIBGUESTFS_BACKEND", "direct")
        .env("LIBGUESTFS_DEBUG", "0")
        .env("LIBGUESTFS_TRACE", "0");
    command
}

impl GuestAccount {
    /// The account with its password hashed as Debian 13 hashes it
    /// (yescrypt, through the host's crypt(3) from Perl), or salted SHA-512
    /// where the host's crypt has no yescrypt.
    pub(crate) fn from_credentials(credentials: GuestCredentials) -> Result<Self, String> {
        Self::yescrypt_with(credentials.clone(), Path::new("perl"))
            .or_else(|_| Self::hash_with(credentials, Path::new("openssl")))
    }
    fn yescrypt_with(credentials: GuestCredentials, executable: &Path) -> Result<Self, String> {
        let mut command = Command::new(executable);
        command.args([
            "-e",
            "local $/; my $p = <STDIN>; my $h = crypt($p, $ARGV[0]); print $h if defined $h",
            &format!("$y$j9T${}", yescrypt_salt()?),
        ]);
        Self::hashed(credentials, command)
    }
    fn hash_with(credentials: GuestCredentials, executable: &Path) -> Result<Self, String> {
        let mut command = Command::new(executable);
        command.args(["passwd", "-6", "-stdin"]);
        Self::hashed(credentials, command)
    }
    fn hashed(credentials: GuestCredentials, command: Command) -> Result<Self, String> {
        let hash = run_private(command, credentials.password.as_bytes(), true)?;
        let password_hash = String::from_utf8(hash)
            .map_err(|_| "invalid password hash output")?
            .trim_end()
            .to_owned();
        let account = Self {
            username: credentials.username,
            password_hash,
            root_uuid: None,
        };
        account.validate()?;
        Ok(account)
    }
    fn validate(&self) -> Result<(), String> {
        validate_guest_username(&self.username)?;
        let parts: Vec<_> = self.password_hash.split('$').collect();
        let crypt64 = |part: &&str| {
            part.bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'.' || c == b'/')
        };
        // $6$salt$hash (SHA-512) or $y$j9T$salt$hash (yescrypt).
        let sha512 = parts.len() == 4
            && parts[1] == "6"
            && (1..=16).contains(&parts[2].len())
            && parts[3].len() == 86;
        let yescrypt = parts.len() == 5
            && parts[1] == "y"
            && parts[2] == "j9T"
            && (1..=86).contains(&parts[3].len())
            && parts[4].len() == 43;
        if !parts[0].is_empty() || !(sha512 || yescrypt) || !parts[2..].iter().all(crypt64) {
            return Err("invalid salted yescrypt or SHA-512 password hash".into());
        }
        if self
            .root_uuid
            .as_deref()
            .is_some_and(|uuid| !valid_uuid(uuid))
        {
            return Err("invalid provisioned root filesystem UUID".into());
        }
        Ok(())
    }
    /// The account's name (uid and gid 1000 in the guest).
    pub(crate) fn username(&self) -> &str {
        &self.username
    }
    /// The root filesystem UUID provisioning gave the VM's disk.
    pub(crate) fn root_uuid(&self) -> Option<&str> {
        self.root_uuid.as_deref()
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
    /// Make the base's disk this VM's own, offline: a root filesystem UUID
    /// and directory hash seed of its own (fstab follows), then the account.
    pub(crate) fn provision(&mut self, disk: &Path) -> Result<(), String> {
        #[cfg(test)]
        if FAIL_PROVISION.with(|fail| fail.replace(false)) {
            return Err("injected offline provisioning failure".into());
        }
        let executable =
            crate::dependencies::require_tool(Path::new("guestfish"), "libguestfs-tools")?;
        self.provision_with(disk, &executable)
    }
    fn provision_with(&mut self, disk: &Path, executable: &Path) -> Result<(), String> {
        self.validate()?;
        let probe = run_private_with_timeout(
            &mut guestfish(executable, disk, false),
            b"run\nlist-filesystems\n",
            true,
            PROVISION_TIMEOUT,
        )?;
        let layout = parse_probe(&String::from_utf8_lossy(&probe))?;
        let uuid = random_uuid()?;
        let script = self.script(&layout, &uuid, &random_hex()?);
        run_private(guestfish(executable, disk, true), script.as_bytes(), false)?;
        File::open(disk)
            .and_then(|file| file.sync_all())
            .map_err(|_| "cannot sync provisioned disk".to_owned())?;
        self.root_uuid = Some(uuid);
        Ok(())
    }
    /// The guestfish commands. The hash crosses as a file the guest's
    /// chpasswd reads, never in a guest command line.
    fn script(&self, layout: &DiskLayout, uuid: &str, machine_id: &str) -> String {
        let username = &self.username;
        let root = &layout.root;
        let staging = format!("/root/.provision-{}", storage::unique_id());
        // The installer asks for a full name; the account name stands in.
        let full_name: String = username
            .chars()
            .enumerate()
            .map(|(index, c)| {
                if index == 0 {
                    c.to_ascii_uppercase()
                } else {
                    c
                }
            })
            .collect();
        // fstab names the root by UUID on the console base (the desktops
        // name /dev/vda and keep their line).
        let guest = format!(
            "set -eu\ntrap 'rm -rf {staging}' EXIT\n\
             sed -i -E 's|^UUID=[0-9A-Fa-f-]+([[:space:]]+/[[:space:]])|UUID={uuid}\\1|' /etc/fstab\n\
             if getent passwd 1000 >/dev/null || getent group 1000 >/dev/null || getent passwd '{username}' >/dev/null || getent group '{username}' >/dev/null; then exit 1; fi\n\
             addgroup --quiet --gid 1000 '{username}'\n\
             adduser --quiet --uid 1000 --gid 1000 --comment '{full_name},,,' --disabled-password '{username}'\n\
             chmod 0700 '/home/{username}'\n\
             for group in {INSTALLER_GROUPS}; do\n\
             \tif getent group \"$group\" >/dev/null; then adduser --quiet '{username}' \"$group\"; fi\n\
             done\n\
             chpasswd -e < {staging}/password\n\
             passwd -l root >/dev/null\n"
        );
        // The directory hash seed has no tune2fs option: debugfs sets it and
        // e2fsck -D reindexes every directory under it. Through the
        // appliance's own tools (guestfish debug, which joins its words
        // without their quotes); a disk keeps its base's seed where that is
        // unavailable.
        let reseed = format!(
            "echo ssv hash_seed random | debugfs -w -f - {root} >/dev/null 2>&1 && e2fsck -fyD {root} >/dev/null 2>&1; test $? -lt 4"
        );
        [
            "run".to_owned(),
            format!("e2fsck-f {root}"),
            format!("set-uuid {root} {uuid}"),
            format!("-debug sh {}", fish_quote(&reseed)),
            format!("mount {root} /"),
            format!("mkdir {staging}"),
            format!("chmod 0700 {staging}"),
            format!(
                "write {staging}/password {}",
                fish_quote(&format!("{username}:{}", self.password_hash))
            ),
            format!("chmod 0600 {staging}/password"),
            format!("write {staging}/provision.sh {}", fish_quote(&guest)),
            format!("sh {}", fish_quote(&format!("sh {staging}/provision.sh"))),
            // The installation's machine ID, its own per VM.
            format!(
                "write /etc/machine-id {}",
                fish_quote(&format!("{machine_id}\n"))
            ),
            "umount-all".to_owned(),
            String::new(),
        ]
        .join("\n")
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
            root_uuid: None,
        }
    }
    /// A guestfish stand-in: the read-only probe lists `filesystems`, the
    /// writable run records its argv and commands.
    fn fake_tool(directory: &Path, fail: bool, filesystems: &str) -> std::path::PathBuf {
        let path = directory.join("fake-tool");
        fs::write(&path, format!("#!/bin/sh\nroot=$(dirname \"$0\")\nif [ \"$1\" = --ro ]; then cat > \"$root/probe\"; printf '{filesystems}'; exit 0; fi\nprintf '%s\\n' \"$@\" > \"$root/argv\"\ncat > \"$root/input\"\ncat \"$root/input\" >&2\nexit {}\n", if fail { 1 } else { 0 })).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }
    #[test]
    fn offline_tool_uses_stdin_and_never_exposes_sensitive_output() {
        let root = std::env::temp_dir().join(format!("ant-account-{}", storage::unique_id()));
        storage::private_dir(&root).unwrap();
        let disk = root.join("disk.qcow2");
        fs::write(&disk, b"unchanged disk fixture").unwrap();
        let mut account = account();
        account
            .provision_with(&disk, &fake_tool(&root, false, "/dev/sda: ext4\\n"))
            .unwrap();
        let uuid = account.root_uuid().unwrap().to_owned();
        assert!(valid_uuid(&uuid), "{uuid}");
        assert_eq!(
            fs::read_to_string(root.join("probe")).unwrap(),
            "run\nlist-filesystems\n"
        );
        let argv = fs::read_to_string(root.join("argv")).unwrap();
        assert!(argv.starts_with("--rw\n--no-progress-bars\n--format=qcow2\n-a\n"));
        assert!(!argv.contains(&account.password_hash));
        assert!(!argv.contains(&account.username));
        let input = fs::read_to_string(root.join("input")).unwrap();
        assert!(input.contains(&account.password_hash));
        // The hash reaches the guest only as a file chpasswd reads.
        for line in input.lines().filter(|line| !line.contains("/password ")) {
            assert!(!line.contains(&account.password_hash), "{line}");
        }
        // A new identity before the root is mounted, then the account.
        let position = |text: &str| input.find(text).unwrap_or_else(|| panic!("{text}"));
        assert!(position("e2fsck-f /dev/sda\n") < position(&format!("set-uuid /dev/sda {uuid}")));
        assert!(
            position("-debug sh \"echo ssv hash_seed random | debugfs -w -f - /dev/sda")
                < position("mount /dev/sda /")
        );
        assert!(input.contains(&format!("UUID={uuid}\\\\1|' /etc/fstab")));
        // The installer's adduser: the full name, its groups (where they
        // exist), a private home; the installation's own machine ID.
        assert!(input.contains("addgroup --quiet --gid 1000 'analyst'"));
        assert!(input.contains(
            "adduser --quiet --uid 1000 --gid 1000 --comment 'Analyst,,,' --disabled-password 'analyst'"
        ));
        assert!(input.contains(&format!("for group in {INSTALLER_GROUPS}; do")));
        assert!(input.contains("chmod 0700 '/home/analyst'"));
        let machine_id = input
            .lines()
            .find_map(|line| line.strip_prefix("write /etc/machine-id \""))
            .unwrap();
        assert!(
            machine_id.len() == 32 + 3 && machine_id.ends_with("\\n\""),
            "{machine_id}"
        );
        assert!(!input.contains("NOPASSWD"));
        assert!(!input.contains("sudoers"));
        assert!(!input.to_lowercase().contains("antinomie"));
        // Another provisioning, another identity.
        let mut again = self::account();
        again
            .provision_with(&disk, &fake_tool(&root, false, "/dev/sda: ext4\\n"))
            .unwrap();
        assert_ne!(again.root_uuid(), Some(uuid.as_str()));
        let error = account
            .provision_with(&disk, &fake_tool(&root, true, "/dev/sda: ext4\\n"))
            .unwrap_err();
        assert!(!error.contains(&account.password_hash));
        assert!(!format!("{account:?}").contains(&account.password_hash));
        assert!(
            account
                .provision_with(&disk, &root.join("missing"))
                .is_err()
        );
        // No single ext4 root: nothing is written.
        fs::remove_file(root.join("input")).unwrap();
        for listing in [
            "/dev/sda: xfs\\n",
            "/dev/sda1: ext4\\n/dev/sda2: ext4\\n",
            "/dev/sdb1: ext4\\n",
        ] {
            assert!(
                account
                    .provision_with(&disk, &fake_tool(&root, false, listing))
                    .is_err()
            );
            assert!(!root.join("input").exists());
        }
        assert_eq!(fs::read(&disk).unwrap(), b"unchanged disk fixture");
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn passwords_are_hashed_as_debian_13_hashes_them() {
        let credentials = GuestCredentials::new("analyst".into(), "x".repeat(20)).unwrap();
        let account = GuestAccount::from_credentials(credentials.clone()).unwrap();
        // yescrypt where the host's crypt(3) has it (libxcrypt), else SHA-512.
        if GuestAccount::yescrypt_with(credentials.clone(), Path::new("perl")).is_ok() {
            assert!(account.password_hash.starts_with("$y$j9T$"));
        }
        assert!(GuestAccount::yescrypt_with(credentials, Path::new("/nonexistent/perl")).is_err());
        let salt = yescrypt_salt().unwrap();
        assert_eq!(salt.len(), 22);
        assert!(matches!(salt.as_bytes()[21], b'.' | b'/' | b'0' | b'1'));
        let mut record = self::account();
        record.password_hash = format!("$y$j9T${}${}", "a".repeat(22), "b".repeat(43));
        record.validate().unwrap();
        for bad in [
            format!("$y$j9T${}${}", "a".repeat(22), "b".repeat(42)),
            format!("$y$jFT${}${}", "a".repeat(22), "b".repeat(43)),
            format!("$y$j9T${}${}", "a:".repeat(11), "b".repeat(43)),
            format!("$5$salt${}", "a".repeat(43)),
        ] {
            record.password_hash = bad;
            assert!(record.validate().is_err());
        }
    }
    #[test]
    fn probe_finds_the_root_on_a_whole_disk_or_a_partition() {
        assert_eq!(parse_probe("/dev/sda: ext4\n").unwrap().root, "/dev/sda");
        assert_eq!(
            parse_probe("/dev/sda1: ext4\n/dev/sda2: unknown\n/dev/sda5: swap\n")
                .unwrap()
                .root,
            "/dev/sda1"
        );
        assert!(parse_probe("").is_err());
        assert!(parse_probe("/dev/sda1; rm -rf /: ext4\n").is_err());
        assert_eq!(fish_quote("a\"b\\c\nd"), "\"a\\\"b\\\\c\\nd\"");
        assert!(valid_uuid("0b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d"));
        for bad in [
            "0B1C2D3E-4F50-4A6B-8C7D-9E0F1A2B3C4D",
            "0b1c2d3e4f504a6b8c7d9e0f1a2b3c4d",
            "",
        ] {
            assert!(!valid_uuid(bad));
        }
        let mut record = account();
        record.root_uuid = Some("not-a-uuid".into());
        assert!(record.validate().is_err());
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
