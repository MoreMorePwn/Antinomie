// SPDX-License-Identifier: GPL-3.0-only
//! Locating a file by inode and reading ranges of it on a starting disk: a
//! base image, and a layer over it that changed one file.
use super::{image::Image, *};
use crate::disks::fixture::{Fixture, require_tools};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

const OLD: &[u8] = b"# old crontab\n17 * * * * root run-parts /etc/cron.hourly\n";
const NEW: &[u8] =
    b"# a crontab the run replaced, and made longer than before\n* * * * * root /tmp/x\n";

/// `(ino, generation)` of `path` in a raw image, as debugfs reports them.
fn stat(image: &Path, path: &str) -> (u64, u32) {
    let output = Command::new("/usr/sbin/debugfs")
        .arg("-R")
        .arg(format!("stat {path}"))
        .arg(image)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    let field = |name: &str| -> u64 {
        let at = text
            .find(name)
            .unwrap_or_else(|| panic!("{name} in {text}"));
        text[at + name.len()..]
            .trim_start()
            .split(|c: char| !c.is_ascii_digit())
            .next()
            .unwrap()
            .parse()
            .unwrap()
    };
    (field("Inode:"), field("Generation:") as u32)
}

struct Layers {
    fixture: Fixture,
    /// The base alone, and the layer over it.
    base: PathBuf,
    top: PathBuf,
    /// The crontab's inode on the base.
    ino: u64,
    generation: u32,
    passwd_ino: u64,
}

fn layers() -> Layers {
    let fixture = Fixture::new();
    let mut images = Vec::new();
    for (name, crontab) in [("base", OLD), ("top", NEW)] {
        let tree = fixture.standard_tree(&format!("{name}-tree"));
        fs::write(tree.join("etc/crontab"), crontab).unwrap();
        let raw = fixture.ext4(&format!("{name}.ext4"), &tree, &[]);
        images.push(raw);
    }
    let (ino, generation) = stat(&images[0], "/etc/crontab");
    let (passwd_ino, _) = stat(&images[0], "/etc/passwd");
    let base = fixture.path("base.qcow2");
    let top = fixture.path("top.qcow2");
    for (raw, out, parent) in [(&images[0], &base, None), (&images[1], &top, Some(&base))] {
        let mut convert = Command::new("qemu-img");
        convert.args(["convert", "-f", "raw", "-O", "qcow2"]);
        if let Some(parent) = parent {
            convert.arg("-B").arg(parent).args(["-F", "qcow2"]);
        }
        assert!(convert.arg(raw).arg(out).status().unwrap().success());
    }
    Layers {
        fixture,
        base,
        top,
        ino,
        generation,
        passwd_ino,
    }
}

fn locate(
    image: &Image,
    path: &str,
    ino: Option<u64>,
    generation: Option<u32>,
) -> Result<DiskLocation, ReadError> {
    match image.handle(
        1,
        DiskRequest::Locate {
            path: path.into(),
            ino,
            generation,
        },
    )? {
        DiskAnswer::Located(location) => Ok(location),
        other => panic!("{other:?}"),
    }
}

fn range(
    image: &Image,
    out: &Path,
    id: u64,
    path: &str,
    offset: u64,
    len: u64,
) -> Result<Vec<u8>, ReadError> {
    match image.handle(
        id,
        DiskRequest::ReadRange {
            path: path.into(),
            offset,
            len,
        },
    )? {
        DiskAnswer::Ranged(receipt) => {
            let bytes = fs::read(out.join(id.to_string())).unwrap();
            assert_eq!(bytes.len() as u64, receipt.len);
            Ok(bytes)
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_file_is_matched_by_its_inode_and_read_from_the_layer_that_holds_it() {
    require_tools!();
    let l = layers();
    let out = l.fixture.path("out");
    fs::create_dir(&out).unwrap();
    let base = Image::open_chain(&l.base, &[], &out);
    let chain = Image::open_chain(&l.top, std::slice::from_ref(&l.base), &out);

    // The base holds the old crontab, and its inode checks out.
    let found = locate(&base, "/etc/crontab", Some(l.ino), Some(l.generation)).unwrap();
    assert_eq!(found.matched, LocationMatch::Inode);
    assert_eq!(found.size, OLD.len() as u64);
    assert_eq!(range(&base, &out, 2, "/etc/crontab", 0, 4096).unwrap(), OLD);
    assert_eq!(
        range(&base, &out, 3, "/etc/crontab", 6, 3).unwrap(),
        &OLD[6..9]
    );
    assert_eq!(
        range(&base, &out, 4, "/etc/crontab", OLD.len() as u64 + 10, 5).unwrap(),
        b""
    );
    // Through the chain the changed layer wins.
    assert_eq!(
        range(&chain, &out, 5, "/etc/crontab", 0, 4096).unwrap(),
        NEW
    );
    assert_eq!(
        locate(&chain, "/etc/crontab", None, None).unwrap().matched,
        LocationMatch::PathOnly
    );

    // The run named no inode: the path is all there is.
    assert_eq!(
        locate(&base, "/etc/crontab", None, None).unwrap().matched,
        LocationMatch::PathOnly
    );
    // Another file's inode, a reused number, a number nothing uses.
    for (ino, generation) in [
        (l.passwd_ino, Some(l.generation)),
        (l.ino, Some(l.generation.wrapping_add(7))),
        (l.ino + 5000, None),
    ] {
        let found = locate(&base, "/etc/crontab", Some(ino), generation).unwrap();
        assert!(
            matches!(found.matched, LocationMatch::Different(_)),
            "{ino} {found:?}"
        );
    }
    // A directory, a missing path and a path through a link are not files here.
    assert!(matches!(
        locate(&base, "/etc", None, None).unwrap().matched,
        LocationMatch::Different(_)
    ));
    assert_eq!(
        locate(&base, "/dev/shm/x", None, None),
        Err(ReadError::NotFound)
    );
    assert!(locate(&base, "/etc/loop/passwd", None, None).is_err());
    // A range read is bounded.
    assert!(matches!(
        range(&base, &out, 6, "/etc/crontab", 0, RANGE_LIMIT + 1),
        Err(ReadError::Limit(_))
    ));
    assert!(range(&base, &out, 7, "/etc", 0, 10).is_err());
}
