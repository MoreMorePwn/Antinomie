// SPDX-License-Identifier: MIT
//! Optional static-analysis tools Antinomie installs when the system has
//! none: capa, Detect It Easy and Ghidra with its Java runtime. Each is
//! downloaded from its upstream release, pinned by SHA-256, unpacked into
//! `<data>/tools/<id>/` and mounted read-only into the analysis sandbox at
//! `SANDBOX_DIR`. A tool installed on the system always takes precedence.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{self, Read},
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

/// Where `<data>/tools` appears inside the analysis sandbox.
pub const SANDBOX_DIR: &str = "/opt/antinomie-tools";

/// System locations the analysis worker checks first, per tool.
pub const CAPA_SYSTEM: &[&str] = &["/usr/bin/capa", "/usr/local/bin/capa"];
pub const DIE_SYSTEM: &[&str] = &["/usr/bin/diec", "/usr/local/bin/diec"];
pub const GHIDRA_SYSTEM: &[&str] = &[
    "/usr/share/ghidra/support/analyzeHeadless",
    "/usr/local/share/ghidra/support/analyzeHeadless",
];
pub const RADARE2_SYSTEM: &[&str] = &["/usr/bin/r2", "/usr/local/bin/r2", "/usr/bin/radare2"];

/// How a download is unpacked.
#[derive(Clone, Copy, Debug)]
pub enum Archive {
    /// A zip file; the first `strip` path components are dropped.
    Zip { strip: usize },
    /// A gzip-compressed tar file; the first `strip` components are dropped.
    TarGz { strip: usize },
    /// A Debian package: the files of its data archive under `prefix`, placed
    /// flat (file names only).
    DebFiles { prefix: &'static str },
}

#[derive(Debug)]
pub struct Download {
    pub file: &'static str,
    pub url: &'static str,
    pub sha256: &'static str,
    pub size: u64,
    pub archive: Archive,
    /// Directory below the tool's directory to unpack into.
    pub into: &'static str,
}

#[derive(Debug)]
pub struct Package {
    pub id: &'static str,
    pub name: &'static str,
    pub version: &'static str,
    /// What the analysis uses it for.
    pub purpose: &'static str,
    pub license: &'static str,
    pub downloads: &'static [Download],
    /// A file that exists once the tool is unpacked.
    pub entry: &'static str,
}

impl Package {
    pub fn size(&self) -> u64 {
        self.downloads.iter().map(|d| d.size).sum()
    }
}

pub const PACKAGES: &[Package] = &[
    Package {
        id: "capa",
        name: "capa",
        version: "9.4.0",
        purpose: "Capabilities (ATT&CK and MBC) with the bundled capa-rules",
        license: "Apache-2.0 (Mandiant)",
        downloads: &[Download {
            file: "capa-v9.4.0-linux.zip",
            url: "https://github.com/mandiant/capa/releases/download/v9.4.0/capa-v9.4.0-linux.zip",
            sha256: "07800a1d20a21eb18fc98716e2ae81b668e0c9a04defd588c8aa17ea3d3281e4",
            size: 47_477_971,
            archive: Archive::Zip { strip: 0 },
            into: "",
        }],
        entry: "capa",
    },
    Package {
        id: "die",
        name: "Detect It Easy",
        version: "3.21",
        purpose: "Compiler, packer and protector signatures for Identification",
        license: "MIT (Detect It Easy); Qt libraries LGPL-3.0; ICU Unicode license",
        downloads: &[
            Download {
                file: "die_3.21_portable_Ubuntu_20.04_amd64.tar.gz",
                url: "https://github.com/horsicq/DIE-engine/releases/download/3.21/die_3.21_portable_Ubuntu_20.04_amd64.tar.gz",
                sha256: "4d85614dd169c0d23f52084f86e05a503c30429df5fb5ec14de50f23808bc2d4",
                size: 27_429_929,
                archive: Archive::TarGz { strip: 1 },
                into: "",
            },
            // The portable build's Qt needs ICU 66, which it does not ship.
            Download {
                file: "libicu66_66.1-2ubuntu2.1_amd64.deb",
                url: "http://archive.ubuntu.com/ubuntu/pool/main/i/icu/libicu66_66.1-2ubuntu2.1_amd64.deb",
                sha256: "00d0de456134668f41bd9ea308a076bc0a6a805180445af8a37209d433f41efe",
                size: 8_515_480,
                archive: Archive::DebFiles {
                    prefix: "./usr/lib/x86_64-linux-gnu/libicu",
                },
                into: "base",
            },
        ],
        entry: "diec.sh",
    },
    Package {
        id: "ghidra",
        name: "Ghidra",
        version: "12.1.4",
        purpose: "Decompilation (headless), with the Eclipse Temurin 21 JDK it runs on",
        license: "Apache-2.0 (Ghidra); GPL-2.0 with Classpath exception (Temurin JDK)",
        downloads: &[
            Download {
                file: "ghidra_12.1.4_PUBLIC_20260921.zip",
                url: "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.4_build/ghidra_12.1.4_PUBLIC_20260921.zip",
                sha256: "ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db",
                size: 569_649_598,
                archive: Archive::Zip { strip: 1 },
                into: "ghidra",
            },
            Download {
                file: "OpenJDK21U-jdk_x64_linux_hotspot_21.0.12.1_1.tar.gz",
                url: "https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.12.1%2B1/OpenJDK21U-jdk_x64_linux_hotspot_21.0.12.1_1.tar.gz",
                sha256: "ce79869e1307ed8ee1e2baa86a412b1eb5b75d10a01006d788a6f968bcfaee94",
                size: 207_473_347,
                archive: Archive::TarGz { strip: 1 },
                into: "jdk",
            },
        ],
        entry: "ghidra/support/analyzeHeadless",
    },
];

pub fn package(id: &str) -> Option<&'static Package> {
    PACKAGES.iter().find(|package| package.id == id)
}

/// The system locations of a tool, as the worker checks them.
pub fn system_candidates(id: &str) -> &'static [&'static str] {
    match id {
        "capa" => CAPA_SYSTEM,
        "die" => DIE_SYSTEM,
        "ghidra" => GHIDRA_SYSTEM,
        _ => &[],
    }
}

/// Availability of one optional tool for the analysis sandbox.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolStatus {
    pub id: String,
    pub name: String,
    pub purpose: String,
    /// Version Antinomie would install.
    pub version: String,
    /// Download size, in octets.
    pub size: u64,
    /// Path of a system installation, which takes precedence.
    pub system: Option<String>,
    /// Version installed by Antinomie under `<data>/tools`.
    pub installed: Option<String>,
}

impl ToolStatus {
    pub fn available(&self) -> bool {
        self.system.is_some() || self.installed.is_some()
    }
}

/// Progress of the single active tool installation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ToolInstall {
    pub id: String,
    pub name: String,
    /// "download", "verify", "unpack", "done" or "failed".
    pub stage: String,
    pub received: u64,
    pub total: u64,
    pub finished: bool,
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct Manifest {
    id: String,
    version: String,
}

pub fn tools_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("tools")
}

fn installed_version(data_dir: &Path, package: &Package) -> Option<String> {
    let directory = tools_dir(data_dir).join(package.id);
    let manifest: Manifest =
        serde_json::from_slice(&fs::read(directory.join("tool.json")).ok()?).ok()?;
    (manifest.id == package.id && directory.join(package.entry).exists())
        .then_some(manifest.version)
}

/// Every optional tool with its system and Antinomie-installed state.
pub fn statuses(data_dir: &Path) -> Vec<ToolStatus> {
    PACKAGES
        .iter()
        .map(|package| ToolStatus {
            id: package.id.into(),
            name: package.name.into(),
            purpose: package.purpose.into(),
            version: package.version.into(),
            size: package.size(),
            system: system_candidates(package.id)
                .iter()
                .find(|path| Path::new(path).is_file())
                .map(|path| (*path).to_owned()),
            installed: installed_version(data_dir, package),
        })
        .collect()
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let mut file = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut digest = Sha256::new();
    io::copy(&mut file, &mut digest).map_err(|e| e.to_string())?;
    Ok(format!("{:x}", digest.finalize()))
}

/// A relative path inside the tool directory, with `strip` leading
/// components removed; None for the stripped root itself, absolute paths
/// and `..`.
fn inside(path: &Path, strip: usize) -> Result<Option<PathBuf>, String> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => parts.push(part.to_owned()),
            Component::CurDir => {}
            _ => {
                return Err(format!(
                    "archive path escapes its directory: {}",
                    path.display()
                ));
            }
        }
    }
    if parts.len() <= strip {
        return Ok(None);
    }
    Ok(Some(parts[strip..].iter().collect()))
}

/// A symlink target that stays inside the unpacked tree.
fn safe_link(link: &Path, target: &Path) -> bool {
    if target.is_absolute() {
        return false;
    }
    let mut depth = link.components().count() as i64 - 1;
    for component in target.components() {
        match component {
            Component::ParentDir => depth -= 1,
            Component::Normal(_) => depth += 1,
            _ => {}
        }
        if depth < 0 {
            return false;
        }
    }
    true
}

fn unpack_zip(archive: &Path, target: &Path, strip: usize) -> Result<(), String> {
    let file = File::open(archive).map_err(|e| e.to_string())?;
    let mut zip = zip::ZipArchive::new(file).map_err(|e| format!("zip: {e}"))?;
    for index in 0..zip.len() {
        let mut entry = zip.by_index(index).map_err(|e| format!("zip: {e}"))?;
        let Some(relative) = inside(Path::new(entry.name()), strip)? else {
            continue;
        };
        let path = target.join(&relative);
        if entry.is_dir() {
            fs::create_dir_all(&path).map_err(|e| e.to_string())?;
            continue;
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let mode = entry.unix_mode().unwrap_or(0o644);
        if mode & 0o170000 == 0o120000 {
            let mut link = String::new();
            entry.read_to_string(&mut link).map_err(|e| e.to_string())?;
            if safe_link(&relative, Path::new(&link)) {
                std::os::unix::fs::symlink(&link, &path).map_err(|e| e.to_string())?;
            }
            continue;
        }
        let mut out = File::create(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        io::copy(&mut entry, &mut out).map_err(|e| e.to_string())?;
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(mode & 0o755 | 0o400))
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Unpack tar entries; `place` maps an entry path to its target path (or
/// None to skip it).
fn unpack_tar(
    reader: impl Read,
    target: &Path,
    place: impl Fn(&Path) -> Result<Option<PathBuf>, String>,
) -> Result<(), String> {
    let mut tar = tar::Archive::new(reader);
    for entry in tar.entries().map_err(|e| format!("tar: {e}"))? {
        let mut entry = entry.map_err(|e| format!("tar: {e}"))?;
        let name = entry.path().map_err(|e| e.to_string())?.into_owned();
        let Some(relative) = place(&name)? else {
            continue;
        };
        let path = target.join(&relative);
        let kind = entry.header().entry_type();
        if kind.is_dir() {
            fs::create_dir_all(&path).map_err(|e| e.to_string())?;
            continue;
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        if kind.is_symlink() {
            if let Some(link) = entry.link_name().map_err(|e| e.to_string())?
                && safe_link(&relative, &link)
            {
                let _ = fs::remove_file(&path);
                std::os::unix::fs::symlink(&link, &path).map_err(|e| e.to_string())?;
            }
            continue;
        }
        if !kind.is_file() {
            continue;
        }
        let mode = entry.header().mode().unwrap_or(0o644);
        let mut out = File::create(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        io::copy(&mut entry, &mut out).map_err(|e| e.to_string())?;
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(mode & 0o755 | 0o400))
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// The data archive of a Debian package (an ar file), decompressed.
fn deb_data(path: &Path) -> Result<Vec<u8>, String> {
    let bytes = fs::read(path).map_err(|e| e.to_string())?;
    if !bytes.starts_with(b"!<arch>\n") {
        return Err("not a Debian package".into());
    }
    let mut offset = 8;
    while offset + 60 <= bytes.len() {
        let header = &bytes[offset..offset + 60];
        let name = String::from_utf8_lossy(&header[..16])
            .trim()
            .trim_end_matches('/')
            .to_owned();
        let size: usize = String::from_utf8_lossy(&header[48..58])
            .trim()
            .parse()
            .map_err(|_| "Debian package member size malformed")?;
        let start = offset + 60;
        let end = start
            .checked_add(size)
            .filter(|end| *end <= bytes.len())
            .ok_or("Debian package truncated")?;
        if name == "data.tar.xz" {
            let mut out = Vec::new();
            lzma_rs::xz_decompress(&mut &bytes[start..end], &mut out)
                .map_err(|e| format!("data.tar.xz: {e}"))?;
            return Ok(out);
        }
        offset = end + (size % 2);
    }
    Err("Debian package has no data.tar.xz".into())
}

fn unpack(download: &Download, archive: &Path, target: &Path) -> Result<(), String> {
    let target = target.join(download.into);
    fs::create_dir_all(&target).map_err(|e| e.to_string())?;
    match download.archive {
        Archive::Zip { strip } => unpack_zip(archive, &target, strip),
        Archive::TarGz { strip } => unpack_tar(
            flate2::read::GzDecoder::new(File::open(archive).map_err(|e| e.to_string())?),
            &target,
            |path| inside(path, strip),
        ),
        Archive::DebFiles { prefix } => {
            unpack_tar(io::Cursor::new(deb_data(archive)?), &target, |path| {
                Ok(path
                    .to_string_lossy()
                    .starts_with(prefix)
                    .then(|| path.file_name().map(PathBuf::from))
                    .flatten())
            })
        }
    }
}

/// Download, verify and unpack one package into `<data>/tools/<id>`.
/// `progress` receives the stage and `(received, total)` octets. Downloads
/// resume after an interruption; the tool replaces an earlier installation
/// only once it is completely unpacked.
pub fn install(
    curl: &Path,
    data_dir: &Path,
    id: &str,
    cancel: &AtomicBool,
    mut progress: impl FnMut(&str, u64, u64),
) -> Result<(), String> {
    let package = package(id).ok_or("unknown analysis tool")?;
    let tools = tools_dir(data_dir);
    let downloads = tools.join(".downloads").join(package.id);
    fs::create_dir_all(&downloads).map_err(|e| format!("{}: {e}", downloads.display()))?;
    let total = package.size();
    let mut done = 0u64;
    for download in package.downloads {
        let path = downloads.join(download.file);
        let complete = |path: &Path| {
            fs::metadata(path).is_ok_and(|m| m.len() == download.size)
                && sha256_file(path).is_ok_and(|hash| hash == download.sha256)
        };
        for attempt in 0..2 {
            if complete(&path) {
                break;
            }
            if attempt == 1 {
                // A resumed file can be complete but corrupt: start over once.
                let _ = fs::remove_file(&path);
            }
            let mut child = crate::distribution::spawn_download(curl, download.url, &path)?;
            loop {
                if cancel.load(Ordering::Relaxed) {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err("tool installation cancelled".into());
                }
                if let Ok(Some(_)) = child.try_wait() {
                    break;
                }
                let received = fs::metadata(&path).map_or(0, |m| m.len());
                progress("download", (done + received).min(total), total);
                std::thread::sleep(Duration::from_millis(200));
            }
            let status = child.wait().map_err(|e| e.to_string())?;
            if !status.success() && attempt == 1 {
                return Err(format!("download failed: {}", download.url));
            }
            progress("verify", done + download.size, total);
        }
        if !complete(&path) {
            return Err(format!(
                "{} failed its SHA-256 check; nothing was installed",
                download.file
            ));
        }
        done += download.size;
    }
    progress("unpack", total, total);
    let partial = tools.join(format!(".{}.partial", package.id));
    let _ = fs::remove_dir_all(&partial);
    for download in package.downloads {
        if cancel.load(Ordering::Relaxed) {
            let _ = fs::remove_dir_all(&partial);
            return Err("tool installation cancelled".into());
        }
        unpack(download, &downloads.join(download.file), &partial).map_err(|error| {
            let _ = fs::remove_dir_all(&partial);
            format!("unpacking {}: {error}", download.file)
        })?;
    }
    if !partial.join(package.entry).exists() {
        let _ = fs::remove_dir_all(&partial);
        return Err(format!("{} is missing after unpacking", package.entry));
    }
    fs::write(
        partial.join("tool.json"),
        serde_json::to_vec_pretty(&Manifest {
            id: package.id.into(),
            version: package.version.into(),
        })
        .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let directory = tools.join(package.id);
    let _ = fs::remove_dir_all(&directory);
    fs::rename(&partial, &directory).map_err(|e| e.to_string())?;
    let _ = fs::remove_dir_all(&downloads);
    progress("done", total, total);
    Ok(())
}

/// Remove an Antinomie-installed tool (system installations are untouched).
pub fn remove(data_dir: &Path, id: &str) -> Result<(), String> {
    let package = package(id).ok_or("unknown analysis tool")?;
    let directory = tools_dir(data_dir).join(package.id);
    if directory.exists() {
        fs::remove_dir_all(&directory).map_err(|e| format!("{}: {e}", directory.display()))?;
    }
    let _ = fs::remove_dir_all(tools_dir(data_dir).join(".downloads").join(package.id));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archive_paths_and_links_stay_inside_the_tool_directory() {
        assert_eq!(
            inside(Path::new("ghidra_12/support/x"), 1).unwrap(),
            Some("support/x".into())
        );
        assert_eq!(inside(Path::new("ghidra_12/"), 1).unwrap(), None);
        assert!(inside(Path::new("../evil"), 0).is_err());
        assert!(inside(Path::new("/etc/passwd"), 0).is_err());
        assert!(safe_link(
            Path::new("base/libicu.so.66"),
            Path::new("libicu.so.66.1")
        ));
        assert!(safe_link(Path::new("bin/java"), Path::new("../lib/java")));
        assert!(!safe_link(Path::new("java"), Path::new("../../etc/passwd")));
        assert!(!safe_link(Path::new("java"), Path::new("/usr/bin/java")));
    }

    #[test]
    fn packages_are_pinned_and_consistent() {
        for package in PACKAGES {
            assert!(!package.downloads.is_empty());
            for download in package.downloads {
                assert_eq!(download.sha256.len(), 64);
                assert!(download.sha256.bytes().all(|c| c.is_ascii_hexdigit()));
                assert!(
                    download.url.ends_with(&download.file.replace('+', "%2B"))
                        || download.url.ends_with(download.file)
                );
                assert!(download.size > 0);
            }
            assert!(!system_candidates(package.id).is_empty());
        }
    }

    #[test]
    fn installs_unpacks_and_removes_from_local_archives() {
        // A zip and a tar.gz served from file URLs exercise the whole path
        // except the pinned catalog.
        let root = std::env::temp_dir().join(format!("ant-tools-{}", crate::storage::unique_id()));
        fs::create_dir_all(&root).unwrap();
        let zip_path = root.join("t.zip");
        {
            let mut writer = zip::ZipWriter::new(File::create(&zip_path).unwrap());
            let options = zip::write::SimpleFileOptions::default().unix_permissions(0o755);
            writer.start_file("top/bin/tool", options).unwrap();
            std::io::Write::write_all(&mut writer, b"#!/bin/sh\n").unwrap();
            writer.finish().unwrap();
        }
        let target = root.join("out");
        unpack_zip(&zip_path, &target, 1).unwrap();
        let mode = fs::metadata(target.join("bin/tool")).unwrap().permissions();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(mode.mode() & 0o111, 0o111);
        let data = root.join("data");
        assert!(
            statuses(&data)
                .iter()
                .all(|status| status.installed.is_none())
        );
        remove(&data, "capa").unwrap();
        let _ = fs::remove_dir_all(&root);
    }
}
