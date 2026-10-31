// SPDX-License-Identifier: GPL-3.0-only
//! Which toolchain a native Debian Minimal kernel build compiles with.
//!
//! The kernel's banner, BTF and compiler-dependent options are Debian 13's
//! only when Debian 13's gcc-14 and binutils build it. A host that has them
//! compiles directly. Any other host compiles in a rootless Debian 13 chroot
//! (`scripts/toolchain_chroot.py`: mmdebstrap in unshare mode, the container
//! builder's package snapshot and exact versions), created on first use and
//! cached under the app's build folder until the user deletes it.

use std::{
    fs,
    path::{Path, PathBuf},
};

/// The folder under the build root that holds the chroot.
const CHROOT_FOLDER: &str = "toolchain";
/// What `scripts/toolchain_chroot.py` writes when the chroot is complete.
const READY_MARKER: &str = "ready.json";
/// The chroot's download (package indexes and archives) and unpacked size, as
/// measured for the pinned snapshot; shown before the first build.
pub const DOWNLOAD_MIB: u64 = 110;
pub const UNPACKED_MIB: u64 = 500;

/// The compiler and linker version lines a host's kernel build records.
pub(crate) type HostToolchain = (Option<String>, Option<String>);

/// Where a native Debian Minimal kernel is compiled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Toolchain {
    /// This host's own gcc and binutils are Debian 13's.
    Host,
    /// The rootless Debian 13 toolchain chroot.
    Chroot,
}

/// Whether `host` already is Debian 13's toolchain (`debian`: the compiler and
/// linker lines of Debian's kernel banner).
pub(crate) fn choose(host: &HostToolchain, debian: &(String, String)) -> Toolchain {
    let same = |found: &Option<String>, wanted: &str| found.as_deref() == Some(wanted);
    if same(&host.0, &debian.0) && same(&host.1, &debian.1) {
        Toolchain::Host
    } else {
        Toolchain::Chroot
    }
}

/// The toolchain a native build of `kind` uses on this host. Only Debian
/// Minimal's kernel needs Debian's: BusyBox and the desktop base keep the
/// host's.
pub fn for_kind(kind: crate::build::Kind) -> Toolchain {
    if kind != crate::build::Kind::DebianMinimal {
        return Toolchain::Host;
    }
    match crate::kit::debian_toolchain() {
        Ok(debian) => choose(crate::build::host_toolchain(), &debian),
        Err(_) => Toolchain::Host,
    }
}

/// The folder of the cached chroot for a build root (`<data>/build`).
pub fn chroot_dir(build_root: &Path) -> PathBuf {
    build_root.join(CHROOT_FOLDER)
}

/// Package pins of the chroot, read from the container builder's Dockerfile so
/// both builders compile with the same packages.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pins {
    /// The snapshot.debian.org timestamp of the package archives.
    pub snapshot: String,
    pub gcc: String,
    pub binutils: String,
}

/// Read the snapshot stamp and the compiler and linker versions from a Dockerfile.
pub fn parse_pins(dockerfile: &str) -> Result<Pins, String> {
    let snapshot = dockerfile
        .lines()
        .find_map(|line| {
            let stamp = line.trim().strip_prefix("stamp=")?.split(';').next()?;
            (stamp.len() == 16 && stamp.ends_with('Z')).then(|| stamp.to_owned())
        })
        .ok_or("the Dockerfile has no snapshot stamp")?;
    let version = |package: &str| {
        dockerfile
            .lines()
            .find_map(|line| {
                let rest = line.trim().strip_prefix(package)?.strip_prefix('=')?;
                rest.split_whitespace().next().map(str::to_owned)
            })
            .ok_or(format!("the Dockerfile does not pin {package}"))
    };
    Ok(Pins {
        snapshot,
        gcc: version("gcc-14")?,
        binutils: version("binutils")?,
    })
}

/// The pins of this app's kit.
pub fn pins() -> Result<Pins, String> {
    let text = crate::container::dockerfile()?;
    parse_pins(&String::from_utf8_lossy(text))
}

/// What the wizard says about the toolchain a native build of `kind` uses.
pub fn describe(kind: crate::build::Kind, build_root: &Path) -> String {
    match for_kind(kind) {
        Toolchain::Host => "compiles with this host's toolchain (gcc and binutils)".to_owned(),
        Toolchain::Chroot => {
            let pins = pins().map_or_else(
                |_| "Debian 13's gcc-14 and binutils".to_owned(),
                |pins| format!("gcc-14 {} and binutils {}", pins.gcc, pins.binutils),
            );
            let dir = chroot_dir(build_root);
            if is_ready(&dir) {
                format!(
                    "compiles in the cached Debian 13 toolchain chroot ({pins}; {} on disk)",
                    crate::byte_size::file_size(size(&dir))
                )
            } else {
                format!(
                    "compiles in a rootless Debian 13 toolchain chroot ({pins}), created on \
                     first use: downloads about {DOWNLOAD_MIB} MiB from snapshot.debian.org \
                     and takes about {UNPACKED_MIB} MiB"
                )
            }
        }
    }
}

/// Whether `dir` holds a finished chroot.
pub fn is_ready(dir: &Path) -> bool {
    dir.join(READY_MARKER).is_file() && dir.join("root/usr/bin").is_dir()
}

/// Bytes the chroot folder occupies (0 when absent).
pub fn size(dir: &Path) -> u64 {
    fn walk(path: &Path) -> u64 {
        let Ok(meta) = fs::symlink_metadata(path) else {
            return 0;
        };
        if !meta.is_dir() {
            return meta.len();
        }
        fs::read_dir(path)
            .into_iter()
            .flatten()
            .flatten()
            .map(|entry| walk(&entry.path()))
            .sum::<u64>()
            + meta.len()
    }
    walk(dir)
}

/// Delete the cached chroot (a later native build creates it again).
pub fn remove(dir: &Path) -> Result<(), String> {
    if !dir.exists() {
        return Ok(());
    }
    // A package may leave a folder without write permission.
    let _ = std::process::Command::new("chmod")
        .args(["-R", "u+rwX"])
        .arg(dir)
        .status();
    fs::remove_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn debian() -> (String, String) {
        (
            "x86_64-linux-gnu-gcc-14 (Debian 14.2.0-19) 14.2.0".into(),
            "GNU ld (GNU Binutils for Debian) 2.44".into(),
        )
    }

    #[test]
    fn only_a_matching_compiler_and_linker_compile_on_the_host() {
        let (cc, ld) = debian();
        assert_eq!(
            choose(&(Some(cc.clone()), Some(ld.clone())), &debian()),
            Toolchain::Host
        );
        let ubuntu = Some("gcc (Ubuntu 15.2.0-4ubuntu4) 15.2.0".to_owned());
        assert_eq!(
            choose(&(ubuntu, Some(ld.clone())), &debian()),
            Toolchain::Chroot
        );
        assert_eq!(choose(&(Some(cc), None), &debian()), Toolchain::Chroot);
        assert_eq!(choose(&(None, None), &debian()), Toolchain::Chroot);
    }

    #[test]
    fn only_debian_minimal_needs_debians_toolchain() {
        use crate::build::Kind;
        assert_eq!(for_kind(Kind::BusyBox), Toolchain::Host);
        assert_eq!(for_kind(Kind::DebianXfce), Toolchain::Host);
    }

    #[test]
    fn pins_come_from_the_container_builders_dockerfile() {
        let pins = pins().unwrap();
        assert_eq!(pins.snapshot, "20261020T213255Z");
        assert_eq!(pins.gcc, "14.2.0-19");
        assert_eq!(pins.binutils, "2.44-3");
        let text = "RUN set -eux; \\\n    stamp=20250101T000000Z; \\\n    gcc-14=14.2.0-1 \\\n    binutils=2.44-1 ; \\\n";
        assert_eq!(parse_pins(text).unwrap().binutils, "2.44-1");
        assert!(parse_pins("RUN true").unwrap_err().contains("snapshot"));
        assert!(
            parse_pins("stamp=20250101T000000Z;")
                .unwrap_err()
                .contains("gcc-14")
        );
    }

    #[test]
    fn the_chroot_cache_is_reported_sized_and_deleted() {
        let root = std::env::temp_dir().join(format!("ant-chroot-{}", crate::storage::unique_id()));
        let dir = chroot_dir(&root);
        assert!(dir.starts_with(&root) && !is_ready(&dir));
        assert_eq!(size(&dir), 0);
        fs::create_dir_all(dir.join("root/usr/bin")).unwrap();
        fs::write(dir.join("root/usr/bin/gcc"), vec![0u8; 5000]).unwrap();
        assert!(!is_ready(&dir), "an unfinished chroot is not ready");
        fs::write(dir.join(READY_MARKER), "{}").unwrap();
        assert!(is_ready(&dir));
        assert!(size(&dir) >= 5002);
        // A read-only folder, as a package may leave, does not stop the delete.
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir.join("root/usr/bin"), fs::Permissions::from_mode(0o555)).unwrap();
        remove(&dir).unwrap();
        assert!(!dir.exists());
        remove(&dir).unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}
