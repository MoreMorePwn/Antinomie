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

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
