// SPDX-License-Identifier: GPL-3.0-only
//! The lived-in state of a cloud VPS profile, written into the VM's own disk
//! before its first start with the profile: cloud-init's data and logs for
//! the instance, the default user and its shell history, login records, and
//! the provider agents' directories as inert stubs
//! ([`CloudProvider::state_files`](crate::stealth::CloudProvider::state_files)).
//!
//! It is per VM, not per base: the base stays one reproducible image for
//! every profile, and each VM gets its own instance id, host name and ages.
//! It works on any base whose root is one ext4 filesystem (BusyBox and
//! Debian Minimal), through the same offline libguestfs run as provisioning.
use super::*;
use crate::stealth::{CloudProvider, Owner, StateFile};

/// Remembers what was written, in the VM's folder.
const MARKER: &str = "cloud-state.json";

#[derive(Serialize, Deserialize, PartialEq, Eq)]
struct Marker {
    provider: String,
    instance_id: String,
}

/// Writes the state of `provider`'s instance for the VM whose system UUID is
/// `uuid` into `disk`, once: a marker in `vm_directory` records it, so a
/// later start with the same profile leaves the disk alone (and a changed
/// profile writes again over it). Returns whether the disk was written.
pub(crate) fn ensure(
    disk: &Path,
    vm_directory: &Path,
    provider: &CloudProvider,
    uuid: &str,
) -> Result<bool, String> {
    let instance_id = provider.instance_id(uuid);
    let marker = Marker {
        provider: provider.id.to_owned(),
        instance_id: instance_id.clone(),
    };
    let path = vm_directory.join(MARKER);
    let known = fs::read(&path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Marker>(&bytes).ok());
    if known.as_ref() == Some(&marker) {
        return Ok(false);
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let files = provider.state_files(&instance_id, &provider.hostname(&instance_id), now);
    let executable = crate::dependencies::require_tool(Path::new("guestfish"), "libguestfs-tools")?;
    write_with(disk, &executable, &files, provider.state.default_user)?;
    storage::atomic_json(&path, &marker)?;
    Ok(true)
}

/// The guestfish script that writes `files` (already staged as `staged`, one
/// local file each) and makes the default `user`.
fn script(root: &str, files: &[StateFile], staged: &Path, user: &str) -> String {
    let mut lines = vec!["run".to_owned(), format!("mount {root} /")];
    if user != "root" {
        lines.push(format!(
            "sh {}",
            fish_quote(&format!(
                "grep -q '^{user}:' /etc/group || echo '{user}:x:1100:' >> /etc/group; \
                 grep -q '^{user}:' /etc/passwd || echo '{user}:x:1100:1100::/home/{user}:/bin/sh' >> /etc/passwd; \
                 mkdir -p /home/{user}; chown {user}:{user} /home/{user}"
            ))
        ));
    }
    for (index, file) in files.iter().enumerate() {
        let remote = fish_quote(&file.path);
        if let Some(parent) = Path::new(&file.path).parent().and_then(Path::to_str) {
            lines.push(format!("mkdir-p {}", fish_quote(parent)));
        }
        let local = staged.join(format!("f{index}"));
        lines.push(format!(
            "upload {} {remote}",
            fish_quote(&local.to_string_lossy())
        ));
        lines.push(format!("chmod 0{:o} {remote}", file.mode));
        if file.owner == Owner::User {
            lines.push(format!(
                "sh {}",
                fish_quote(&format!("chown {user}:{user} {}", file.path))
            ));
        }
        lines.push(format!("utimens {remote} {0} 0 {0} 0", file.mtime));
    }
    lines.push("umount-all".to_owned());
    lines.push(String::new());
    lines.join("\n")
}

fn write_with(
    disk: &Path,
    executable: &Path,
    files: &[StateFile],
    user: &str,
) -> Result<(), String> {
    let probe = run_private(&mut guestfish(executable, disk, false), PROBE, true)?;
    let layout = parse_probe(&String::from_utf8_lossy(&probe))?;
    let staged = std::env::temp_dir().join(format!("ant-cloudstate-{}", storage::unique_id()));
    storage::private_dir(&staged).map_err(|error| error.to_string())?;
    let result = (|| {
        for (index, file) in files.iter().enumerate() {
            fs::write(staged.join(format!("f{index}")), &file.content)
                .map_err(|error| format!("cloud state: {error}"))?;
        }
        let commands = staged.join("commands.fish");
        fs::write(&commands, script(&layout.root, files, &staged, user))
            .map_err(|error| format!("cloud state: {error}"))?;
        let mut command = guestfish(executable, disk, true);
        command.arg("-f").arg(&commands);
        run_private(&mut command, b"", false)?;
        File::open(disk)
            .and_then(|file| file.sync_all())
            .map_err(|_| "cannot sync the VM disk".to_owned())
    })();
    let _ = fs::remove_dir_all(&staged);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stealth::CLOUDS;

    #[test]
    fn the_script_makes_the_user_uploads_each_file_and_ages_it() {
        let provider = &CLOUDS[0];
        let files = provider.state_files("ins-abc", "VM-3-12-ubuntu", 2_000_000_000);
        let text = script("/dev/sda", &files, Path::new("/stage"), "ubuntu");
        assert!(text.starts_with("run\nmount /dev/sda /\n"));
        let home = "/home/";
        assert!(text.contains(&format!("echo 'ubuntu:x:1100:1100::{home}ubuntu:/bin/sh'")));
        assert!(text.contains("upload \"/stage/f0\" \"/var/lib/cloud/data/instance-id\""));
        assert!(text.contains("chmod 0644 \"/var/lib/cloud/data/instance-id\""));
        assert!(text.contains(&format!("chown ubuntu:ubuntu {home}ubuntu/.bash_history")));
        assert!(text.contains(&format!(
            "utimens \"/var/lib/cloud/data/instance-id\" {0} 0 {0} 0",
            2_000_000_000u64 - 12 * 86_400
        )));
        assert!(text.ends_with("umount-all\n"));
        let root = script("/dev/sda", &files, Path::new("/stage"), "root");
        assert!(!root.contains("/etc/passwd"));
    }

    #[test]
    fn a_vm_whose_state_is_written_is_left_alone_until_its_profile_changes() {
        let directory = std::env::temp_dir().join(format!("ant-cs-{}", storage::unique_id()));
        fs::create_dir_all(&directory).unwrap();
        let uuid = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0";
        let provider = &CLOUDS[0];
        let marker = Marker {
            provider: provider.id.into(),
            instance_id: provider.instance_id(uuid),
        };
        storage::atomic_json(&directory.join(MARKER), &marker).unwrap();
        // The disk is never opened when the marker matches.
        assert!(!ensure(Path::new("/nonexistent.qcow2"), &directory, provider, uuid).unwrap());
        assert!(
            ensure(
                Path::new("/nonexistent.qcow2"),
                &directory,
                &CLOUDS[1],
                uuid
            )
            .is_err()
        );
        let _ = fs::remove_dir_all(&directory);
    }
}
