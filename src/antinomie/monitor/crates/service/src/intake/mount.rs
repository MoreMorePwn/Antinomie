// SPDX-License-Identifier: GPL-3.0-only
//! The `noexec` check of design 4.2: staged uploads are plain files in
//! `inbox/uploads/`, which must be on a `noexec` mount when it is a separate
//! volume. The service checks the mount flag at start.

use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mount {
    pub point: PathBuf,
    pub options: Vec<String>,
}

impl Mount {
    pub fn noexec(&self) -> bool {
        self.options.iter().any(|option| option == "noexec")
    }
}

/// `\040` and the other octal escapes of a `mountinfo` path.
fn unescape(field: &str) -> String {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'\\'
            && at + 3 < bytes.len()
            && bytes[at + 1..at + 4]
                .iter()
                .all(|b| (b'0'..=b'7').contains(b))
        {
            let value =
                (bytes[at + 1] - b'0') * 64 + (bytes[at + 2] - b'0') * 8 + (bytes[at + 3] - b'0');
            out.push(value);
            at += 4;
        } else {
            out.push(bytes[at]);
            at += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The mounts of a `/proc/self/mountinfo` text: mount point and the per-mount
/// options (field 6).
pub fn parse_mountinfo(text: &str) -> Vec<Mount> {
    text.lines()
        .filter_map(|line| {
            let mut fields = line.split(' ');
            let point = unescape(fields.nth(4)?);
            let options = fields.next()?;
            Some(Mount {
                point: PathBuf::from(point),
                options: options.split(',').map(str::to_owned).collect(),
            })
        })
        .collect()
}

/// The mount a path lives on: the one with the longest mount point that is a
/// parent of the path.
pub fn mount_of<'a>(mounts: &'a [Mount], path: &Path) -> Option<&'a Mount> {
    mounts
        .iter()
        .filter(|mount| path.starts_with(&mount.point))
        .max_by_key(|mount| mount.point.components().count())
}

/// Where the staging directory lives, for the log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Volume {
    /// The same mount as the data directory: nothing more is required.
    SameAsData,
    /// A separate volume, mounted `noexec`.
    SeparateNoexec,
}

/// Check the mount flag. `uploads` and `data_dir` must exist (paths are
/// resolved). A separate volume without `noexec` is an error.
pub fn check_staging_volume(
    uploads: &Path,
    data_dir: &Path,
    mountinfo: &str,
) -> Result<Volume, String> {
    let uploads = uploads
        .canonicalize()
        .map_err(|e| format!("{}: {e}", uploads.display()))?;
    let data = data_dir
        .canonicalize()
        .map_err(|e| format!("{}: {e}", data_dir.display()))?;
    let mounts = parse_mountinfo(mountinfo);
    let (Some(on_uploads), Some(on_data)) = (mount_of(&mounts, &uploads), mount_of(&mounts, &data))
    else {
        // No mount table to read (a container without /proc/self/mountinfo):
        // the check cannot say no.
        return Ok(Volume::SameAsData);
    };
    if on_uploads.point == on_data.point {
        return Ok(Volume::SameAsData);
    }
    if on_uploads.noexec() {
        Ok(Volume::SeparateNoexec)
    } else {
        Err(format!(
            "{} is on a separate volume ({}) that is not mounted noexec; staged uploads must not be executable",
            uploads.display(),
            on_uploads.point.display()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TABLE: &str = "\
24 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
25 24 8:2 / /srv/data rw,relatime shared:2 - ext4 /dev/sda2 rw
26 25 8:3 / /srv/data/inbox/uploads rw,nosuid,nodev,noexec,relatime - ext4 /dev/sda3 rw
27 24 8:4 / /srv/with\\040space rw,relatime - ext4 /dev/sda4 rw
28 24 8:5 / /srv/exec rw,relatime - ext4 /dev/sda5 rw
";

    #[test]
    fn mount_points_and_options_are_read() {
        let mounts = parse_mountinfo(TABLE);
        assert_eq!(mounts.len(), 5);
        assert_eq!(mounts[3].point, PathBuf::from("/srv/with space"));
        assert!(mounts[2].noexec() && !mounts[1].noexec());
        let on = |p: &str| mount_of(&mounts, Path::new(p)).unwrap().point.clone();
        assert_eq!(
            on("/srv/data/inbox/uploads/u_x/data"),
            PathBuf::from("/srv/data/inbox/uploads")
        );
        assert_eq!(on("/srv/data/inbox/other"), PathBuf::from("/srv/data"));
        assert_eq!(on("/etc"), PathBuf::from("/"));
    }

    #[test]
    fn a_separate_volume_must_be_noexec() {
        let root = std::env::temp_dir().join(format!("ant-mount-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let data = root.join("data");
        let uploads = data.join("inbox/uploads");
        std::fs::create_dir_all(&uploads).unwrap();
        let (data_c, uploads_c) = (
            data.canonicalize().unwrap(),
            uploads.canonicalize().unwrap(),
        );
        let table = |upload_options: &str, same: bool| {
            let mut text = format!(
                "24 1 8:1 / / rw - ext4 /dev/sda1 rw\n25 24 8:2 / {} rw - ext4 /dev/sda2 rw\n",
                data_c.display()
            );
            if !same {
                text += &format!(
                    "26 25 8:3 / {} {upload_options} - ext4 /dev/sda3 rw\n",
                    uploads_c.display()
                );
            }
            text
        };
        assert_eq!(
            check_staging_volume(&uploads, &data, &table("", true)),
            Ok(Volume::SameAsData)
        );
        assert_eq!(
            check_staging_volume(&uploads, &data, &table("rw,noexec,nosuid", false)),
            Ok(Volume::SeparateNoexec)
        );
        let error =
            check_staging_volume(&uploads, &data, &table("rw,relatime", false)).unwrap_err();
        assert!(error.contains("not mounted noexec"), "{error}");
        // No mount table at all: cannot refuse.
        assert_eq!(
            check_staging_volume(&uploads, &data, ""),
            Ok(Volume::SameAsData)
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
