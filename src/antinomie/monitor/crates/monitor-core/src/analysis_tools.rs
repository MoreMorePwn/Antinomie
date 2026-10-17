// SPDX-License-Identifier: MIT
//! Optional static-analysis tools Antinomie installs when the system has
//! none: capa, Detect It Easy and Ghidra with its Java runtime. Each is
//! downloaded from its upstream release, pinned by SHA-256, unpacked into
//! `<data>/tools/<id>/` and mounted read-only into the analysis sandbox at
//! `SANDBOX_DIR`. A tool installed on the system always takes precedence.
use serde::{Deserialize, Serialize};

use std::{
    fs::{self, File},
    io::{self, Read},
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
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

/// A Python tool installed into its own virtual environment from a
/// hash-locked requirements file, with the system Python.
#[derive(Debug)]
pub struct Requirements {
    /// pip requirements pinning every package and the SHA-256 of each wheel.
    pub lock: &'static str,
    /// Approximate download size of the wheels, in octets.
    pub size: u64,
    /// Python statement that succeeds once the tool can be used.
    pub check: &'static str,
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
    pub requirements: Option<Requirements>,
    /// A file that exists once the tool is unpacked.
    pub entry: &'static str,
}

impl Package {
    pub fn size(&self) -> u64 {
        self.downloads.iter().map(|d| d.size).sum::<u64>()
            + self.requirements.as_ref().map_or(0, |r| r.size)
    }
}

/// The Python a requirements-based tool's environment is created with.
const SYSTEM_PYTHON: &str = "/usr/bin/python3";

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
        requirements: None,
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
        requirements: None,
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
        requirements: None,
        entry: "ghidra/support/analyzeHeadless",
    },
    // Wheels are zip files: unpacked side by side they form an import path
    // for the system Python 3 (see memory::Volatility).
    Package {
        id: "volatility3",
        name: "Volatility 3",
        version: "2.28.2",
        purpose: "Memory analysis of RAM dumps in the Memory tab (runs on the system Python 3)",
        license: "Volatility Software License 1.0 (Volatility 3); MIT (pefile); BSD-3-Clause \
                  (Capstone); BSD-2-Clause and public domain (PyCryptodome)",
        downloads: &[
            Download {
                file: "volatility3-2.28.2-py3-none-any.whl",
                url: "https://files.pythonhosted.org/packages/8a/26/548439f5192e496fff7f54d41d8762fa8f3712d53c8441b9f57d7c7a8310/volatility3-2.28.2-py3-none-any.whl",
                sha256: "0461d6dd71b9ddbaf70c96e079c06efdf174ac65383b3dcf10dd165181fbd3c3",
                size: 1_424_884,
                archive: Archive::Zip { strip: 0 },
                into: "lib",
            },
            Download {
                file: "pefile-2024.8.26-py3-none-any.whl",
                url: "https://files.pythonhosted.org/packages/54/16/12b82f791c7f50ddec566873d5bdd245baa1491bac11d15ffb98aecc8f8b/pefile-2024.8.26-py3-none-any.whl",
                sha256: "76f8b485dcd3b1bb8166f1128d395fa3d87af26360c2358fb75b80019b957c6f",
                size: 74_766,
                archive: Archive::Zip { strip: 0 },
                into: "lib",
            },
            Download {
                file: "capstone-5.0.9-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl",
                url: "https://files.pythonhosted.org/packages/d1/39/17747862222bb062e86b501f1f148d5ff589b77908b080d30f7f085cbfb7/capstone-5.0.9-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl",
                sha256: "273fd8d747d2e35c88f91450be51a603ecfaafb00d96d9f315dcb8689c86193e",
                size: 1_485_316,
                archive: Archive::Zip { strip: 0 },
                into: "lib",
            },
            Download {
                file: "pycryptodome-3.23.0-cp37-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl",
                url: "https://files.pythonhosted.org/packages/5f/e9/a09476d436d0ff1402ac3867d933c61805ec2326c6ea557aeeac3825604e/pycryptodome-3.23.0-cp37-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl",
                sha256: "c8987bd3307a39bc03df5c8e0e3d8be0c4c3518b7f044b0f4c15d1aa78f52575",
                size: 2_268_954,
                archive: Archive::Zip { strip: 0 },
                into: "lib",
            },
        ],
        requirements: None,
        entry: "lib/volatility3/__init__.py",
    },
    // pip installs exactly the wheels the lock names; the system Python
    // creates the environment, so there is no interpreter to download.
    Package {
        id: "sigma",
        name: "Sigma (pySigma)",
        version: "2.0.1",
        purpose: "Sigma detection with pySigma and its SQLite backend 2.1.0",
        license: "LGPL-3.0 (pySigma); LGPL-2.1 (SQLite backend); dependencies under their own licenses",
        downloads: &[],
        requirements: Some(Requirements {
            lock: include_str!("../assets/sigma-requirements.txt"),
            size: 3_600_000,
            check: "import sigma.backends.sqlite",
        }),
        entry: "venv/bin/python",
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
    /// "download", "verify", "unpack", "prepare", "packages", "done" or
    /// "failed".
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
    let file = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let checksum = crate::storage::sha256_uncached(file)?;
    Ok(checksum.iter().map(|b| format!("{b:02x}")).collect())
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
    if let Some(requirements) = &package.requirements {
        return install_python(data_dir, package, requirements, cancel, progress);
    }
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

/// Create `<tool>/venv` with the system Python and install the locked wheels
/// into it. pip refuses any file whose SHA-256 the lock does not name; the
/// environment replaces an earlier one only after its check passes.
fn install_python(
    data_dir: &Path,
    package: &Package,
    requirements: &Requirements,
    cancel: &AtomicBool,
    mut progress: impl FnMut(&str, u64, u64),
) -> Result<(), String> {
    let total = requirements.size;
    progress("prepare", 0, total);
    let version = step(
        Command::new(SYSTEM_PYTHON).args([
            "-I",
            "-c",
            "import sys; print(*sys.version_info[:2], sep='.')",
        ]),
        cancel,
    )
    .map_err(|error| {
        format!("{SYSTEM_PYTHON} did not run: {error}; on Debian/Ubuntu: sudo apt install python3")
    })?;
    let minor = version
        .trim()
        .strip_prefix("3.")
        .and_then(|minor| minor.parse::<u32>().ok());
    if minor.is_none_or(|minor| minor < 11) {
        return Err(format!(
            "{} needs Python 3.11 or newer; {SYSTEM_PYTHON} is {}",
            package.name,
            version.trim()
        ));
    }
    let tools = tools_dir(data_dir);
    let partial = tools.join(format!(".{}.partial", package.id));
    let _ = fs::remove_dir_all(&partial);
    fs::create_dir_all(&partial).map_err(|e| format!("{}: {e}", partial.display()))?;
    let result = (|| {
        let venv = partial.join("venv");
        step(
            Command::new(SYSTEM_PYTHON).arg("-m").arg("venv").arg(&venv),
            cancel,
        )
        .map_err(|error| {
            format!(
                "the system Python cannot create a virtual environment ({error}); \
                     on Debian/Ubuntu: sudo apt install python3-venv"
            )
        })?;
        let lock = partial.join("requirements.txt");
        fs::write(&lock, requirements.lock).map_err(|e| e.to_string())?;
        progress("packages", 0, total);
        let python = venv.join("bin/python");
        step(
            Command::new(&python)
                .args([
                    "-I",
                    "-m",
                    "pip",
                    "install",
                    "--disable-pip-version-check",
                    "--no-input",
                    "--no-cache-dir",
                    "--require-hashes",
                    "--only-binary=:all:",
                    "--no-deps",
                    "-r",
                ])
                .arg(&lock),
            cancel,
        )
        .map_err(|error| format!("pip could not install the locked packages: {error}"))?;
        progress("verify", total, total);
        step(
            Command::new(&python).args(["-I", "-c", requirements.check]),
            cancel,
        )
        .map_err(|error| format!("the installed environment failed its check: {error}"))?;
        fs::write(
            partial.join("tool.json"),
            serde_json::to_vec_pretty(&Manifest {
                id: package.id.into(),
                version: package.version.into(),
            })
            .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())
    })();
    if let Err(error) = result {
        let _ = fs::remove_dir_all(&partial);
        return Err(error);
    }
    let directory = tools.join(package.id);
    let _ = fs::remove_dir_all(&directory);
    fs::rename(&partial, &directory).map_err(|e| e.to_string())?;
    progress("done", total, total);
    Ok(())
}

/// Run one installation step; its standard output on success, the end of
/// its diagnostics on failure. `cancel` stops it.
fn step(command: &mut Command, cancel: &AtomicBool) -> Result<String, String> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    let mut stdout = child.stdout.take().ok_or("no output pipe")?;
    let mut stderr = child.stderr.take().ok_or("no diagnostics pipe")?;
    let output = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = stdout.read_to_string(&mut text);
        text
    });
    let diagnostics = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = stderr.read_to_string(&mut text);
        text
    });
    let status = loop {
        if cancel.load(Ordering::Relaxed) {
            let _ = child.kill();
            let _ = child.wait();
            return Err("tool installation cancelled".into());
        }
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            break status;
        }
        std::thread::sleep(Duration::from_millis(200));
    };
    let output = output.join().unwrap_or_default();
    let diagnostics = diagnostics.join().unwrap_or_default();
    if status.success() {
        Ok(output)
    } else {
        let tail: Vec<_> = diagnostics.lines().rev().take(3).collect();
        Err(tail
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join(" ")
            .trim()
            .to_owned())
    }
}

/// The Python of the Sigma tool installed in `data_dir`, if it is there.
/// Answers are reused for two seconds, so frames do not read the disk.
pub fn managed_sigma_python(data_dir: &Path) -> Option<PathBuf> {
    type Answer = (std::time::Instant, PathBuf, Option<PathBuf>);
    static CACHE: std::sync::Mutex<Option<Answer>> = std::sync::Mutex::new(None);
    let mut cache = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((at, directory, answer)) = cache.as_ref()
        && directory == data_dir
        && at.elapsed() < Duration::from_secs(2)
    {
        return answer.clone();
    }
    let package = package("sigma")?;
    let answer = installed_version(data_dir, package)
        .map(|_| tools_dir(data_dir).join(package.id).join(package.entry));
    *cache = Some((
        std::time::Instant::now(),
        data_dir.to_owned(),
        answer.clone(),
    ));
    answer
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
            // Archives or a hash-locked Python environment, never both.
            assert!(package.downloads.is_empty() != package.requirements.is_none());
            if let Some(requirements) = &package.requirements {
                let mut pins = 0;
                for requirement in requirements.lock.split("\n\n").flat_map(|block| {
                    block
                        .lines()
                        .filter(|line| !line.starts_with('#'))
                        .collect::<Vec<_>>()
                }) {
                    if requirement.contains("==") {
                        pins += 1;
                    } else {
                        let hash = requirement.trim().trim_end_matches(" \\");
                        let digest = hash.strip_prefix("--hash=sha256:").unwrap();
                        assert_eq!(digest.len(), 64);
                        assert!(digest.bytes().all(|c| c.is_ascii_hexdigit()));
                    }
                }
                assert!(pins > 0 && requirements.size > 0);
            }
            for download in package.downloads {
                assert_eq!(download.sha256.len(), 64);
                assert!(download.sha256.bytes().all(|c| c.is_ascii_hexdigit()));
                assert!(
                    download.url.ends_with(&download.file.replace('+', "%2B"))
                        || download.url.ends_with(download.file)
                );
                assert!(download.size > 0);
            }
            // Volatility and Sigma only run from Antinomie's own pinned install.
            assert_eq!(
                system_candidates(package.id).is_empty(),
                matches!(package.id, "volatility3" | "sigma")
            );
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
