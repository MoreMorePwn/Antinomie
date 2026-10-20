// SPDX-License-Identifier: MIT
//! Test fixtures: small ext4 images built with `mkfs.ext4 -d` and `debugfs`,
//! and qcow2 chains built with `qemu-img`, all in a private temp folder that
//! is deleted on drop. Tests that need the tools skip when they are missing.
use std::{
    ffi::OsStr,
    fs,
    os::unix::{ffi::OsStrExt, fs::symlink},
    path::{Path, PathBuf},
    process::Command,
};

/// The e2fsprogs and QEMU tools the fixtures need.
pub(crate) fn tools_available() -> bool {
    ["mkfs.ext4", "debugfs", "qemu-img"].iter().all(|tool| {
        crate::dependencies::executable(Path::new(tool)).is_some()
            || ["/sbin", "/usr/sbin"]
                .iter()
                .any(|dir| Path::new(dir).join(tool).is_file())
    })
}

/// Skip a test (with a note) when the image tools are missing.
macro_rules! require_tools {
    () => {
        if !$crate::disks::fixture::tools_available() {
            eprintln!("skipped: mkfs.ext4, debugfs and qemu-img are needed");
            return;
        }
    };
}
pub(crate) use require_tools;

pub(crate) struct Fixture {
    pub root: PathBuf,
}

/// The default size of a fixture filesystem, in MiB.
const IMAGE_MIB: u64 = 32;

fn tool(name: &str) -> Command {
    for dir in ["/sbin", "/usr/sbin"] {
        let path = Path::new(dir).join(name);
        if path.is_file() {
            return Command::new(path);
        }
    }
    Command::new(name)
}

fn run(mut command: Command) {
    let output = command.output().expect("fixture tool starts");
    assert!(
        output.status.success(),
        "{:?} failed: {}{}",
        command,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

impl Fixture {
    pub fn new() -> Self {
        let root = std::env::temp_dir().join(format!("ant-disks-{}", crate::storage::unique_id()));
        crate::storage::private_dir(&root).unwrap();
        Self { root }
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    /// The tree every fixture image holds.
    pub fn standard_tree(&self, name: &str) -> PathBuf {
        let tree = self.path(name);
        for directory in [
            "etc",
            "bin",
            "lib",
            "tmp",
            "home/user",
            "var/log",
            "a/b",
            "empty",
        ] {
            fs::create_dir_all(tree.join(directory)).unwrap();
        }
        fs::write(tree.join("etc/passwd"), "root:x:0:0:root:/root:/bin/sh\n").unwrap();
        let mut elf = b"\x7fELF".to_vec();
        elf.extend((0..60u8).map(|byte| byte.wrapping_mul(7)));
        fs::write(tree.join("bin/busybox"), &elf).unwrap();
        fs::write(tree.join("lib/libc.so.6"), vec![0x5a; 9000]).unwrap();
        fs::write(tree.join("home/user/.hidden"), "secret").unwrap();
        fs::write(tree.join("home/user/notes.txt"), "remember the milk\n").unwrap();
        fs::write(tree.join("var/log/messages.log"), "boot ok\n").unwrap();
        fs::write(tree.join("a/b/deep.txt"), "deep").unwrap();
        // A link to a file that is not there, and a link to a directory: both
        // are shown and never followed.
        symlink("/etc/shadow", tree.join("etc/shadow-link")).unwrap();
        symlink("/etc", tree.join("etc/loop")).unwrap();
        // A name that is not UTF-8 and one with control characters.
        fs::write(tree.join(OsStr::from_bytes(b"tmp/bad\xffname")), "x").unwrap();
        fs::write(tree.join("tmp/new\nline"), "y").unwrap();
        tree
    }

    /// A raw ext4 image of `tree`, with owners, modes and special files set
    /// through `debugfs`, and `commands` run on it afterwards.
    pub fn ext4(&self, name: &str, tree: &Path, commands: &[&str]) -> PathBuf {
        let image = self.path(name);
        let file = fs::File::create(&image).unwrap();
        file.set_len(IMAGE_MIB * 1024 * 1024).unwrap();
        let mut mkfs = tool("mkfs.ext4");
        mkfs.args(["-q", "-F", "-b", "4096", "-L", "fixture", "-d"])
            .arg(tree)
            .arg(&image);
        run(mkfs);
        let mut script = vec![
            "sif /home/user uid 1000".to_string(),
            "sif /home/user gid 1000".into(),
            "sif /home/user/.hidden uid 1000".into(),
            "sif /bin/busybox mode 0100755".into(),
            // `mknod` names the entry as typed: change to the root first.
            "cd /".into(),
            "mknod fifo p".into(),
            "mknod null c 1 3".into(),
            // Fixed times, so two images of one tree compare equal.
            "sif fifo mtime 20010909014640".into(),
            "sif null mtime 20010909014640".into(),
        ];
        script.extend(commands.iter().map(|command| command.to_string()));
        self.debugfs(&image, &script);
        image
    }

    /// Run `debugfs -w` commands on `image`.
    pub fn debugfs(&self, image: &Path, commands: &[String]) {
        let file = self.path(&format!("{}.debugfs", crate::storage::unique_id()));
        fs::write(&file, commands.join("\n")).unwrap();
        let mut debugfs = tool("debugfs");
        debugfs.arg("-w").arg("-f").arg(&file).arg(image);
        run(debugfs);
    }

    /// The first data block of a file of `image`.
    pub fn first_block(&self, image: &Path, path: &str) -> u64 {
        let output = tool("debugfs")
            .args(["-R", &format!("bmap {path} 0")])
            .arg(image)
            .output()
            .unwrap();
        String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .last()
            .unwrap()
            .trim()
            .parse()
            .unwrap()
    }

    /// Set the access and modification time of every entry of `tree`
    /// (links themselves, not their targets) to `seconds` after the epoch.
    pub fn stamp_tree(&self, tree: &Path, seconds: i64) {
        use rustix::fs::{AtFlags, CWD, Timespec, Timestamps, utimensat};
        fn walk(path: &Path, found: &mut Vec<PathBuf>) {
            found.push(path.to_path_buf());
            if fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_dir()) {
                for entry in fs::read_dir(path).unwrap().flatten() {
                    walk(&entry.path(), found);
                }
            }
        }
        let mut paths = Vec::new();
        walk(tree, &mut paths);
        let time = Timespec {
            tv_sec: seconds,
            tv_nsec: 0,
        };
        for path in paths {
            utimensat(
                CWD,
                &path,
                &Timestamps {
                    last_access: time,
                    last_modification: time,
                },
                AtFlags::SYMLINK_NOFOLLOW,
            )
            .unwrap();
        }
    }

    /// The standard raw image.
    pub fn standard_image(&self) -> PathBuf {
        let tree = self.standard_tree("tree");
        self.ext4("standard.ext4", &tree, &[])
    }

    /// A three-layer qcow2 chain `base <- mid <- top`: each layer's image
    /// holds one more file (`etc/layer-1`, `etc/layer-2`) than the last.
    /// Returns the top.
    pub fn chain(&self) -> PathBuf {
        let tree = self.standard_tree("chain-tree");
        let mut parent: Option<PathBuf> = None;
        for layer in 0..3 {
            if layer > 0 {
                fs::write(
                    tree.join(format!("etc/layer-{layer}")),
                    format!("written in layer {layer}\n"),
                )
                .unwrap();
            }
            let raw = self.ext4(&format!("layer-{layer}.ext4"), &tree, &[]);
            let qcow = self.path(&format!("layer-{layer}.qcow2"));
            let mut convert = Command::new("qemu-img");
            convert.args(["convert", "-f", "raw", "-O", "qcow2"]);
            if let Some(parent) = &parent {
                convert.args(["-B"]).arg(parent).args(["-F", "qcow2"]);
            }
            convert.arg(&raw).arg(&qcow);
            run(convert);
            fs::remove_file(&raw).unwrap();
            parent = Some(qcow);
        }
        parent.unwrap()
    }
}

/// Which partition table [`Fixture::partitioned`] writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Scheme {
    Gpt,
    Mbr,
}

/// Where the partitions of [`Fixture::partitioned`] are, in bytes.
pub(crate) const OTHER_START: u64 = 1024 * 1024;
pub(crate) const OTHER_LENGTH: u64 = 4 * 1024 * 1024;
pub(crate) const EXT4_START: u64 = 5 * 1024 * 1024;

/// A GPT type GUID in its on-disk (mixed-endian) bytes.
pub(crate) fn guid_bytes(text: &str) -> [u8; 16] {
    let hex: Vec<u8> = text
        .replace('-', "")
        .as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    let mut bytes = [0u8; 16];
    bytes[0..4].copy_from_slice(&[hex[3], hex[2], hex[1], hex[0]]);
    bytes[4..6].copy_from_slice(&[hex[5], hex[4]]);
    bytes[6..8].copy_from_slice(&[hex[7], hex[6]]);
    bytes[8..16].copy_from_slice(&hex[8..16]);
    bytes
}

impl Fixture {
    /// A raw disk with a partition table: partition 1 holds 4 MiB of
    /// non-filesystem bytes (the "unsupported filesystem"), partition 2 the
    /// ext4 image `ext4`. Returns the disk and the table's byte layout is
    /// [`OTHER_START`]/[`OTHER_LENGTH`]/[`EXT4_START`].
    pub fn partitioned(&self, name: &str, scheme: Scheme, ext4: &Path) -> PathBuf {
        use std::io::{Seek, SeekFrom, Write};
        let filesystem = fs::read(ext4).unwrap();
        let disk_size = EXT4_START + filesystem.len() as u64 + 1024 * 1024;
        let path = self.path(name);
        let mut disk = fs::File::create(&path).unwrap();
        disk.set_len(disk_size).unwrap();
        disk.seek(SeekFrom::Start(OTHER_START)).unwrap();
        disk.write_all(&vec![0xAB; OTHER_LENGTH as usize]).unwrap();
        disk.seek(SeekFrom::Start(EXT4_START)).unwrap();
        disk.write_all(&filesystem).unwrap();
        let sectors = disk_size / 512;
        let spans = [
            (OTHER_START / 512, (OTHER_START + OTHER_LENGTH) / 512 - 1),
            (
                EXT4_START / 512,
                (EXT4_START + filesystem.len() as u64) / 512 - 1,
            ),
        ];
        match scheme {
            Scheme::Mbr => {
                let mut sector = [0u8; 512];
                for (slot, (first, last)) in spans.iter().enumerate() {
                    let entry = &mut sector[446 + slot * 16..462 + slot * 16];
                    entry[4] = if slot == 0 { 0x82 } else { 0x83 };
                    entry[8..12].copy_from_slice(&(*first as u32).to_le_bytes());
                    entry[12..16].copy_from_slice(&((last - first + 1) as u32).to_le_bytes());
                }
                sector[510] = 0x55;
                sector[511] = 0xAA;
                disk.seek(SeekFrom::Start(0)).unwrap();
                disk.write_all(&sector).unwrap();
            }
            Scheme::Gpt => {
                let mut protective = [0u8; 512];
                protective[446 + 4] = 0xEE;
                protective[446 + 8..446 + 12].copy_from_slice(&1u32.to_le_bytes());
                protective[446 + 12..446 + 16]
                    .copy_from_slice(&((sectors - 1) as u32).to_le_bytes());
                protective[510] = 0x55;
                protective[511] = 0xAA;
                let mut header = [0u8; 512];
                header[..8].copy_from_slice(b"EFI PART");
                header[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
                header[12..16].copy_from_slice(&92u32.to_le_bytes());
                header[24..32].copy_from_slice(&1u64.to_le_bytes());
                header[32..40].copy_from_slice(&(sectors - 1).to_le_bytes());
                header[40..48].copy_from_slice(&34u64.to_le_bytes());
                header[48..56].copy_from_slice(&(sectors - 34).to_le_bytes());
                header[72..80].copy_from_slice(&2u64.to_le_bytes());
                header[80..84].copy_from_slice(&128u32.to_le_bytes());
                header[84..88].copy_from_slice(&128u32.to_le_bytes());
                let mut entries = vec![0u8; 128 * 128];
                let kinds = [
                    "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F",
                    "4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709",
                ];
                for (slot, (first, last)) in spans.iter().enumerate() {
                    let entry = &mut entries[slot * 128..(slot + 1) * 128];
                    entry[..16].copy_from_slice(&guid_bytes(kinds[slot]));
                    entry[16] = 1 + slot as u8;
                    entry[32..40].copy_from_slice(&first.to_le_bytes());
                    entry[40..48].copy_from_slice(&last.to_le_bytes());
                    for (position, unit) in ["swap", "root"][slot].encode_utf16().enumerate() {
                        entry[56 + position * 2..58 + position * 2]
                            .copy_from_slice(&unit.to_le_bytes());
                    }
                }
                disk.seek(SeekFrom::Start(0)).unwrap();
                disk.write_all(&protective).unwrap();
                disk.write_all(&header).unwrap();
                disk.write_all(&entries).unwrap();
            }
        }
        path
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
