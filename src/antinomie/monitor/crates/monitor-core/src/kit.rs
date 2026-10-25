//! The base build kit the app carries.
//!
//! `build.rs` embeds the repository files a base build needs, in their
//! repository layout: the orchestrator, kernel build script, image recipes,
//! core patch series and the pinned Debian source package (except its large
//! upstream tarball, which `fetch_orig` downloads and checks). The kit is
//! written once per content digest under the app's build directory.

use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

include!(concat!(env!("OUT_DIR"), "/kit_files.rs"));

const ADAPTER: &str = "src/antinomie/packaging/debian-6.12.94-1-trixie/adapter.conf";
const COMPLETE: &str = ".antinomie-kit-complete";

fn kit_file(path: &str) -> Result<&'static [u8], String> {
    KIT_FILES
        .iter()
        .find(|(name, _)| *name == path)
        .map(|(_, bytes)| *bytes)
        .ok_or_else(|| format!("build kit lacks {path}"))
}

/// SHA-256 over every kit file's name and contents.
pub(crate) fn digest() -> String {
    let mut digest = Sha256::new();
    for (name, bytes) in KIT_FILES {
        digest.update((name.len() as u64).to_le_bytes());
        digest.update(name.as_bytes());
        digest.update((bytes.len() as u64).to_le_bytes());
        digest.update(bytes);
    }
    format!("{:x}", digest.finalize())
}

/// Write the kit to `<root>/kit-<digest>` unless it is already complete, remove
/// older kits, and return the kit directory.
pub(crate) fn materialize(root: &Path) -> Result<PathBuf, String> {
    let error = |path: &Path, e: std::io::Error| format!("{}: {e}", path.display());
    fs::create_dir_all(root).map_err(|e| error(root, e))?;
    let name = format!("kit-{}", &digest()[..16]);
    let dir = root.join(&name);
    if !dir.join(COMPLETE).is_file() {
        let staging = root.join(format!("kit-staging-{}", crate::storage::unique_id()));
        let result = (|| -> Result<(), String> {
            for (path, bytes) in KIT_FILES {
                let target = staging.join(path);
                let parent = target.parent().ok_or("kit path has no parent")?;
                fs::create_dir_all(parent).map_err(|e| error(parent, e))?;
                fs::write(&target, bytes).map_err(|e| error(&target, e))?;
                let mode = if path.ends_with(".py") || path.ends_with(".sh") {
                    0o755
                } else {
                    0o644
                };
                fs::set_permissions(&target, fs::Permissions::from_mode(mode))
                    .map_err(|e| error(&target, e))?;
            }
            fs::write(staging.join(COMPLETE), digest()).map_err(|e| error(&staging, e))?;
            if dir.exists() {
                fs::remove_dir_all(&dir).map_err(|e| error(&dir, e))?;
            }
            fs::rename(&staging, &dir).map_err(|e| error(&dir, e))
        })();
        if staging.exists() {
            let _ = fs::remove_dir_all(&staging);
        }
        result?;
    }
    for entry in fs::read_dir(root).map_err(|e| error(root, e))?.flatten() {
        let other = entry.file_name().to_string_lossy().into_owned();
        if other.starts_with("kit-") && other != name {
            let _ = fs::remove_dir_all(entry.path());
        }
    }
    Ok(dir)
}

const SERIES_DIR: &str = "src/antinomie/core/6.12/";
const KERNEL_SCRIPT: &str = "scripts/build-monitor-kernel.sh";

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// The patch-series hash `build-base.py` and the kernel build script use:
/// SHA-256 of `sha256sum` lines for the core patches in name order.
pub(crate) fn series_hash() -> String {
    let mut patches: Vec<_> = KIT_FILES
        .iter()
        .filter_map(|(name, bytes)| Some((name.strip_prefix(SERIES_DIR)?, *bytes)))
        .filter(|(name, _)| name.ends_with(".patch"))
        .collect();
    patches.sort_by(|a, b| a.0.cmp(b.0));
    let listing: String = patches
        .iter()
        .map(|(name, bytes)| format!("{}  {name}\n", sha256_hex(bytes)))
        .collect();
    sha256_hex(listing.as_bytes())
}

/// Where the built kernel for a kernel profile (`minimal`, `debian`) of this
/// kit is cached. The kernel depends only on the series, the kernel build
/// script and the profile, never on the image answers.
pub(crate) fn kernel_cache(root: &Path, kernel_profile: &str) -> Result<PathBuf, String> {
    let script = sha256_hex(kit_file(KERNEL_SCRIPT)?);
    let key = sha256_hex(format!("{kernel_profile}\n{}\n{script}", series_hash()).as_bytes());
    Ok(root
        .join("kernels")
        .join(format!("kernel-{kernel_profile}-{}.tar", &key[..16])))
}

/// Where the Debian root filesystem bootstrapped for `name` (a desktop, or
/// `minimal` for the console base) is cached; the image recipe checks inside
/// that it matches the recipe and answers and is recent enough.
pub(crate) fn image_cache(root: &Path, name: &str) -> PathBuf {
    root.join("images")
        .join(format!("rootfs-debian-{name}.tar"))
}

/// The kernel compiler cache: a directory for builds on this host, a tarball
/// that the builder VM unpacks and returns.
pub(crate) fn ccache_dir(root: &Path) -> PathBuf {
    root.join("ccache")
}
pub(crate) fn ccache_archive(root: &Path) -> PathBuf {
    root.join("ccache.tar")
}

/// Keep only `current` among the cached kernels of its profile.
pub(crate) fn prune_kernel_cache(current: &Path) {
    let (Some(directory), Some(name)) = (current.parent(), current.file_name()) else {
        return;
    };
    let name = name.to_string_lossy();
    let Some(prefix) = name
        .rsplit_once('-')
        .map(|(prefix, _)| format!("{prefix}-"))
    else {
        return;
    };
    for entry in fs::read_dir(directory).into_iter().flatten().flatten() {
        let other = entry.file_name().to_string_lossy().into_owned();
        if other.starts_with(&prefix) && other != name {
            let _ = fs::remove_file(entry.path());
        }
    }
}

/// The kit's packed copy as a tar archive (for the QEMU builder), written to `path`.
pub(crate) fn write_tar(kit: &Path, path: &Path) -> Result<(), String> {
    let status = Command::new("tar")
        .arg("-C")
        .arg(kit)
        .args(["--owner=0", "--group=0", "--numeric-owner", "-cf"])
        .arg(path)
        .args(KIT_FILES.iter().map(|(name, _)| *name))
        .stdin(Stdio::null())
        .status()
        .map_err(|e| format!("tar: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("packing the build kit failed: {status}"))
    }
}

/// The upstream tarball the kit does not carry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OrigInput {
    pub name: String,
    pub size: u64,
    pub sha256: String,
    pub sha1: String,
}

/// Read the tarball name and SHA-256 from the adapter and its SHA-1 and size
/// from the `.dsc` (the snapshot.debian.org fallback is addressed by SHA-1).
pub(crate) fn orig_input() -> Result<OrigInput, String> {
    let adapter = String::from_utf8_lossy(kit_file(ADAPTER)?).into_owned();
    let value = |key: &str| {
        adapter.lines().find_map(|line| {
            line.trim()
                .strip_prefix(key)?
                .strip_prefix('=')
                .map(|v| v.trim_matches(|c| c == '"' || c == '\'').to_string())
        })
    };
    let orig = value("INPUT_ORIG").ok_or("adapter lacks INPUT_ORIG")?;
    let sha256 = value("INPUT_SHA_ORIG").ok_or("adapter lacks INPUT_SHA_ORIG")?;
    let dsc_path = value("INPUT_DSC").ok_or("adapter lacks INPUT_DSC")?;
    let name = orig.rsplit('/').next().unwrap_or(&orig).to_string();
    let dsc = String::from_utf8_lossy(kit_file(&dsc_path)?).into_owned();
    let mut section = "";
    let mut sha1_entry = None;
    for line in dsc.lines() {
        if !line.starts_with(' ') {
            section = line.split(':').next().unwrap_or_default();
            continue;
        }
        let fields: Vec<_> = line.split_whitespace().collect();
        if section == "Checksums-Sha1" && fields.len() == 3 && fields[2] == name {
            sha1_entry = Some((fields[0].to_string(), fields[1].parse::<u64>().ok()));
        }
    }
    let (sha1, size) = sha1_entry.ok_or("dsc lacks the tarball's SHA-1")?;
    Ok(OrigInput {
        name,
        size: size.ok_or("dsc has an invalid tarball size")?,
        sha256,
        sha1,
    })
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let mut file = fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut digest = Sha256::new();
    let mut chunk = vec![0; 1 << 20];
    loop {
        let len = file.read(&mut chunk).map_err(|e| e.to_string())?;
        if len == 0 {
            break;
        }
        digest.update(&chunk[..len]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

/// Download the upstream tarball into `inputs` once, from the Debian pool or,
/// when the pool no longer has it, from snapshot.debian.org; verify SHA-256.
pub(crate) fn fetch_orig(
    curl: &Path,
    inputs: &Path,
    cancel: &AtomicBool,
    mut progress: impl FnMut(u64, u64),
) -> Result<PathBuf, String> {
    let input = orig_input()?;
    fs::create_dir_all(inputs).map_err(|e| format!("{}: {e}", inputs.display()))?;
    let target = inputs.join(&input.name);
    if target.is_file() && sha256_file(&target)? == input.sha256 {
        return Ok(target);
    }
    let partial = inputs.join(format!("{}.part", input.name));
    let urls = [
        format!(
            "https://deb.debian.org/debian/pool/main/l/linux/{}",
            input.name
        ),
        format!("https://snapshot.debian.org/file/{}", input.sha1),
    ];
    let mut failures = Vec::new();
    for url in &urls {
        let mut child = crate::distribution::spawn_download(curl, url, &partial)?;
        let status = loop {
            if cancel.load(Ordering::Relaxed) {
                let _ = child.kill();
                let _ = child.wait();
                return Err("build cancelled".into());
            }
            if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
                break status;
            }
            progress(
                fs::metadata(&partial).map_or(0, |meta| meta.len()),
                input.size,
            );
            std::thread::sleep(Duration::from_millis(200));
        };
        if status.success() && sha256_file(&partial)? == input.sha256 {
            fs::rename(&partial, &target).map_err(|e| format!("{}: {e}", target.display()))?;
            return Ok(target);
        }
        let _ = fs::remove_file(&partial);
        failures.push(format!("{url}: {status}"));
    }
    Err(format!(
        "could not download {} with the pinned SHA-256 ({})",
        input.name,
        failures.join("; ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kit_carries_the_orchestrator_recipes_series_and_source_package() {
        let names: Vec<_> = KIT_FILES.iter().map(|(name, _)| *name).collect();
        for required in [
            "scripts/build-base.py",
            "scripts/build-monitor-kernel.sh",
            "scripts/build-monitor-image.py",
            "scripts/build-debian-image.py",
            "scripts/make-kernel-symbols.py",
            ADAPTER,
            "src/debian/linux_6.12.94-1.dsc",
            "src/debian/linux_6.12.94-1.debian.tar.xz",
            "src/antinomie/monitor/protocol/revisions.json",
            "LICENSE",
        ] {
            assert!(names.contains(&required), "{required}");
        }
        // The whole series, starting with the patch that reports its identity.
        let series = names
            .iter()
            .filter(|name| name.starts_with(SERIES_DIR) && name.ends_with(".patch"))
            .count();
        let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../..");
        let on_disk = fs::read_dir(repo.join(SERIES_DIR))
            .unwrap()
            .filter(|entry| {
                entry
                    .as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".patch")
            })
            .count();
        assert_eq!(series, on_disk);
        assert!(
            names
                .iter()
                .any(|name| name.starts_with("src/antinomie/core/6.12/0001-"))
        );
        let input = orig_input().unwrap();
        assert_eq!(input.name, "linux_6.12.94.orig.tar.xz");
        assert_eq!(input.size, 151_297_764);
        assert_eq!(input.sha256.len(), 64);
        assert_eq!(input.sha1.len(), 40);
    }

    #[test]
    fn series_hash_matches_the_build_scripts_and_names_the_kernel_cache() {
        let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../..");
        let shell = Command::new("sh")
            .arg("-c")
            .arg("sha256sum -- *.patch | sha256sum")
            .current_dir(repo.join(SERIES_DIR))
            .output()
            .unwrap();
        let expected = String::from_utf8(shell.stdout).unwrap();
        assert_eq!(series_hash(), expected.split_whitespace().next().unwrap());
        let root = Path::new("/data/build");
        let minimal = kernel_cache(root, "minimal").unwrap();
        let debian = kernel_cache(root, "debian").unwrap();
        assert!(minimal.starts_with("/data/build/kernels"));
        assert_ne!(minimal, debian);
        assert!(
            debian
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("kernel-debian-")
        );
        let dir = std::env::temp_dir().join(format!("ant-kernels-{}", crate::storage::unique_id()));
        fs::create_dir_all(&dir).unwrap();
        for name in [
            "kernel-debian-old.tar",
            "kernel-minimal-old.tar",
            "kernel-debian-new.tar",
        ] {
            fs::write(dir.join(name), b"x").unwrap();
        }
        prune_kernel_cache(&dir.join("kernel-debian-new.tar"));
        let mut left: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        left.sort();
        assert_eq!(left, ["kernel-debian-new.tar", "kernel-minimal-old.tar"]);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn materialize_writes_once_and_replaces_older_kits() {
        let root = std::env::temp_dir().join(format!("ant-kit-{}", crate::storage::unique_id()));
        fs::create_dir_all(root.join("kit-0000000000000000")).unwrap();
        let dir = materialize(&root).unwrap();
        assert!(dir.join("scripts/build-base.py").is_file());
        let mode = fs::metadata(dir.join("scripts/build-base.py"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o755);
        assert!(!root.join("kit-0000000000000000").exists());
        fs::write(dir.join("scripts/build-base.py"), b"edited").unwrap();
        assert_eq!(materialize(&root).unwrap(), dir);
        assert_eq!(
            fs::read(dir.join("scripts/build-base.py")).unwrap(),
            b"edited"
        );
        let tar = root.join("kit.tar");
        write_tar(&dir, &tar).unwrap();
        assert!(fs::metadata(&tar).unwrap().len() > 1 << 20);
        fs::remove_dir_all(root).unwrap();
    }
}
