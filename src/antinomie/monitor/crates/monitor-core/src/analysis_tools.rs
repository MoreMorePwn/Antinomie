// SPDX-License-Identifier: GPL-3.0-only
//! Optional static-analysis tools Antinomie installs when the system has
//! none: capa, Detect It Easy, Ghidra with its Java runtime, Volatility 3,
//! MemNixFS, Sigma, Magika and the gdb consoles GEF (bata24) and pwndbg. Each
//! is downloaded from its upstream release, pinned by SHA-256, unpacked into `<data>/tools/<id>/` and mounted read-only into the
//! analysis sandbox at `SANDBOX_DIR`. A tool installed on the system takes
//! precedence, except Magika, which the Properties panel looks for here first.
use serde::{Deserialize, Serialize};

use std::{
    fs::{self, File},
    io::{self, Read, Seek},
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
pub const MAGIKA_SYSTEM: &[&str] = &["/usr/bin/magika", "/usr/local/bin/magika"];
pub const PWNDBG_SYSTEM: &[&str] = &["/usr/bin/pwndbg", "/usr/local/bin/pwndbg"];
/// Magika as the sandbox sees the managed copy.
pub const MAGIKA_MANAGED: &str = "/opt/antinomie-tools/magika/magika";

/// How a download is unpacked.
#[derive(Clone, Copy, Debug)]
pub enum Archive {
    /// A zip file; the first `strip` path components are dropped.
    Zip { strip: usize },
    /// A gzip-compressed tar file; the first `strip` components are dropped.
    TarGz { strip: usize },
    /// An xz-compressed tar file; the first `strip` components are dropped.
    TarXz { strip: usize },
    /// One file kept as it is, under the name of `Download::file`.
    File,
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
                url: "https://archive.ubuntu.com/ubuntu/pool/main/i/icu/libicu66_66.1-2ubuntu2.1_amd64.deb",
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
    // The upstream Linux build links the system's libyara, libsnappy, liblzma
    // and libmagic, but needs libfmt 9 and libfuse 3 sonames that newer
    // distributions no longer ship; the two Debian libraries come beside it.
    // See memory::memnixfs for the checks and the sandbox it runs in.
    Package {
        id: "memnixfs",
        name: "MemNixFS",
        version: "1.2",
        purpose: "Linux memory forensics of RAM dumps in the Memory tab (runs offline in the sandbox)",
        license: "Apache-2.0 (MemNixFS); MIT (fmt 9); LGPL-2.1-or-later (libfuse 3)",
        downloads: &[
            Download {
                file: "MemNixFS-1.2-Linux.tar.gz",
                url: "https://github.com/MemNixFS/MemNixFS/releases/download/v1.2/MemNixFS-1.2-Linux.tar.gz",
                sha256: "7fbdf390f213dbadb4ef0042999d676387e1e44c4b8678ee9f51af299a15b20f",
                size: 2_197_017,
                archive: Archive::TarGz { strip: 1 },
                into: "",
            },
            Download {
                file: "libfmt9_9.1.0+ds1-2_amd64.deb",
                url: "https://deb.debian.org/debian/pool/main/f/fmtlib/libfmt9_9.1.0+ds1-2_amd64.deb",
                sha256: "c3d405b6eabb1a521b60a57509826707f0e6f92b41cdfaae06bf1d7c37da2166",
                size: 112_952,
                archive: Archive::DebFiles {
                    prefix: "./usr/lib/x86_64-linux-gnu/libfmt.so.9",
                },
                into: "lib",
            },
            Download {
                file: "libfuse3-3_3.14.0-4_amd64.deb",
                url: "https://deb.debian.org/debian/pool/main/f/fuse3/libfuse3-3_3.14.0-4_amd64.deb",
                sha256: "bf535cec5e965823fd03199b4029f9e9f3952111eb12824b5d2b96c8cca1a918",
                size: 88_108,
                archive: Archive::DebFiles {
                    prefix: "./usr/lib/x86_64-linux-gnu/libfuse3.so.3",
                },
                into: "lib",
            },
        ],
        requirements: None,
        entry: "memnixfs",
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
    // Google's prebuilt command-line tool: one executable with its model
    // built in. It links only the system's libc and libstdc++.
    Package {
        id: "magika",
        name: "Magika",
        version: "1.1.0",
        purpose: "Deep-learning file-type detection for the Properties panel",
        license: "Apache-2.0 (Google)",
        downloads: &[Download {
            file: "magika-cli-x86_64-unknown-linux-gnu.tar.xz",
            url: "https://github.com/google/magika/releases/download/cli/v1.1.0/magika-cli-x86_64-unknown-linux-gnu.tar.xz",
            sha256: "6b4c1010c84d1f4f06205ccef4597f1690bcd7744f46d841eee26426bc100485",
            size: 8_625_112,
            archive: Archive::TarXz { strip: 1 },
            into: "",
        }],
        requirements: None,
        entry: "magika",
    },
    // A single Python script for the system's gdb (which must have Python).
    // bata24's fork has no releases, so the commit is the version.
    Package {
        id: "gef",
        name: "GEF (bata24)",
        version: "2026-10-20 (fc085a6)",
        purpose: "gdb console of the Debugger tab (needs gdb with Python on this system)",
        license: "MIT (bata24; derived from GEF by hugsy)",
        downloads: &[Download {
            file: "gef.py",
            url: "https://raw.githubusercontent.com/bata24/gef/fc085a60be334d38d498296187344e9e7d558587/gef.py",
            sha256: "fabcdc13c8c7a81ceaa2af891f6ce4695d623adef98c8f2ccf365bbbf4df90ce",
            size: 9_278_078,
            archive: Archive::File,
            into: "",
        }],
        requirements: None,
        entry: "gef.py",
    },
    // The upstream portable build: its own gdb, Python and libraries, started
    // through bin/pwndbg, so it needs nothing from the system.
    Package {
        id: "pwndbg",
        name: "pwndbg",
        version: "2026.09.15",
        purpose: "gdb console of the Debugger tab (portable build with its own gdb 17.2)",
        license: "MIT (pwndbg); the build bundles GDB 17.2 (GPL-3.0-or-later), Python (PSF) \
                  and other libraries under their own licenses",
        downloads: &[Download {
            file: "pwndbg_2026.09.15_x86_64-portable.tar.xz",
            url: "https://github.com/pwndbg/pwndbg/releases/download/2026.09.15/pwndbg_2026.09.15_x86_64-portable.tar.xz",
            sha256: "7ba64666ee595885ba4b0e073f85e423829103e9fdbe921ba4eef1acd9150803",
            size: 108_200_928,
            archive: Archive::TarXz { strip: 1 },
            into: "",
        }],
        requirements: None,
        entry: "bin/pwndbg",
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
        "magika" => MAGIKA_SYSTEM,
        "pwndbg" => PWNDBG_SYSTEM,
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

/// The most memory (KiB) one xz block may ask of the decoder: its
/// dictionary plus the decoder's own tables. xz -9 uses 64 MiB; a stream
/// that wants more is refused rather than allocated.
const XZ_MEMORY_LIMIT_KB: u32 = 256 * 1024;

/// An xz decoder that remembers why it failed: tar only sees a stream that
/// ended early, and the decoder's error is the better message.
struct XzSource<R: Read> {
    xz: lzma_rust2::XzReader<io::BufReader<R>>,
    failure: Option<String>,
}

impl<R: Read> Read for XzSource<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.xz.read(buf).inspect_err(|e| {
            self.failure.get_or_insert_with(|| e.to_string());
        })
    }
}

/// Unpack a tar.xz as it is decoded: nothing but the decoder's dictionary
/// and one copy buffer is held, whatever the archive's size (pwndbg is
/// 665 MiB unpacked).
fn unpack_tar_xz(
    reader: impl Read,
    target: &Path,
    place: impl Fn(&Path) -> Result<Option<PathBuf>, String>,
) -> Result<(), String> {
    let mut source = XzSource {
        xz: lzma_rust2::XzReader::new_mem_limit(
            io::BufReader::new(reader),
            false,
            XZ_MEMORY_LIMIT_KB,
        ),
        failure: None,
    };
    let unpacked = unpack_tar(&mut source, target, place);
    // A broken stream is the cause of a tar that ended early.
    if let Some(failure) = source.failure {
        return Err(format!("xz: {failure}"));
    }
    unpacked?;
    // Tar stops at its end marker; the rest of the stream (padding, block
    // checks, index, footer) is still verified.
    io::copy(&mut source, &mut io::sink())
        .map(|_| ())
        .map_err(|e| format!("xz: {e}"))
}

/// The data archive of a Debian package (an ar file): its `data.tar.xz`
/// member, positioned for reading.
fn deb_data(path: &Path) -> Result<io::Take<File>, String> {
    let mut file = File::open(path).map_err(|e| e.to_string())?;
    let mut magic = [0u8; 8];
    if file.read_exact(&mut magic).is_err() || &magic != b"!<arch>\n" {
        return Err("not a Debian package".into());
    }
    loop {
        let mut header = [0u8; 60];
        match file.read_exact(&mut header) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.to_string()),
        }
        let name = String::from_utf8_lossy(&header[..16])
            .trim()
            .trim_end_matches('/')
            .to_owned();
        let size: u64 = String::from_utf8_lossy(&header[48..58])
            .trim()
            .parse()
            .map_err(|_| "Debian package member size malformed")?;
        if name == "data.tar.xz" {
            return Ok(file.take(size));
        }
        let skip = i64::try_from(size + size % 2).map_err(|_| "Debian package truncated")?;
        file.seek(io::SeekFrom::Current(skip))
            .map_err(|e| e.to_string())?;
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
        Archive::TarXz { strip } => unpack_tar_xz(
            File::open(archive).map_err(|e| e.to_string())?,
            &target,
            |path| inside(path, strip),
        ),
        Archive::File => {
            let path = target.join(download.file);
            fs::copy(archive, &path).map_err(|e| format!("{}: {e}", path.display()))?;
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).map_err(|e| e.to_string())
        }
        Archive::DebFiles { prefix } => unpack_tar_xz(deb_data(archive)?, &target, |path| {
            Ok(path
                .to_string_lossy()
                .starts_with(prefix)
                .then(|| path.file_name().map(PathBuf::from))
                .flatten())
        })
        .map_err(|e| format!("data.tar.xz: {e}")),
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
    use std::io::Write;

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
            // Volatility, MemNixFS, Sigma and GEF only run from Antinomie's own
            // pinned install.
            assert_eq!(
                system_candidates(package.id).is_empty(),
                matches!(package.id, "volatility3" | "memnixfs" | "sigma" | "gef")
            );
        }
        // Magika is the official release binary of exactly the listed version,
        // and the sandbox path the Properties panel runs is the package entry.
        let magika = package("magika").unwrap();
        let [download] = magika.downloads else {
            panic!("one Magika download");
        };
        assert_eq!(
            download.url,
            format!(
                "https://github.com/google/magika/releases/download/cli/v{}/{}",
                magika.version, download.file
            )
        );
        assert!(matches!(download.archive, Archive::TarXz { strip: 1 }));
        assert_eq!(
            MAGIKA_MANAGED,
            format!("{SANDBOX_DIR}/{}/{}", magika.id, magika.entry)
        );
        assert!(MAGIKA_SYSTEM.iter().all(|path| path.ends_with("/magika")));
    }

    /// A single-block xz stream, the layout whose decoder most easily ends
    /// up holding the whole archive.
    fn xz_bytes(data: &[u8]) -> Vec<u8> {
        let mut writer =
            lzma_rust2::XzWriter::new(Vec::new(), lzma_rust2::XzOptions::with_preset(1)).unwrap();
        writer.write_all(data).unwrap();
        writer.finish().unwrap()
    }

    /// A tar with a small, a large pseudo-random and a small file.
    fn tar_with_a_large_file(size: usize) -> Vec<u8> {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let large: Vec<u8> = (0..size)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 32) as u8
            })
            .collect();
        let mut builder = tar::Builder::new(Vec::new());
        for (name, body) in [
            ("top/a", &b"first"[..]),
            ("top/big", &large),
            ("top/z", b"last"),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, name, body).unwrap();
        }
        builder.into_inner().unwrap()
    }

    /// Counts the octets the decoder has taken from the archive.
    struct Counted<R>(R, std::rc::Rc<std::cell::Cell<usize>>);

    impl<R: Read> Read for Counted<R> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let len = self.0.read(buf)?;
            self.1.set(self.1.get() + len);
            Ok(len)
        }
    }

    #[test]
    fn a_tar_xz_is_unpacked_while_it_is_decoded_not_after_it_is_held() {
        let root =
            std::env::temp_dir().join(format!("ant-tools-xzs-{}", crate::storage::unique_id()));
        fs::create_dir_all(&root).unwrap();
        let tar = tar_with_a_large_file(12 << 20);
        let xz = xz_bytes(&tar);
        assert!(xz.len() > 11 << 20, "the large file does not compress");
        let consumed = std::rc::Rc::new(std::cell::Cell::new(0));
        let seen = std::cell::RefCell::new(Vec::new());
        unpack_tar_xz(
            Counted(io::Cursor::new(&xz), consumed.clone()),
            &root,
            |path| {
                seen.borrow_mut().push(consumed.get());
                inside(path, 1)
            },
        )
        .unwrap();
        let seen = seen.into_inner();
        assert_eq!(seen.len(), 3);
        // A decoder that buffers the archive has read all of it before the
        // first entry is placed; a streaming one has read a few buffers.
        assert!(
            seen[0] < 1 << 20,
            "read {} octets for the first entry",
            seen[0]
        );
        assert!(
            seen[1] < 1 << 20,
            "read {} octets for the second entry",
            seen[1]
        );
        // The last entry cannot start before most of the large one is decoded.
        assert!(seen[2] > 10 << 20, "read {} octets for the last", seen[2]);
        assert_eq!(
            consumed.get(),
            xz.len(),
            "the whole stream is read and checked"
        );
        assert_eq!(fs::read(root.join("z")).unwrap(), b"last");
        assert_eq!(fs::metadata(root.join("big")).unwrap().len(), 12 << 20);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_damaged_or_oversized_xz_stream_is_reported_as_the_xz_stream() {
        let root =
            std::env::temp_dir().join(format!("ant-tools-xze-{}", crate::storage::unique_id()));
        fs::create_dir_all(&root).unwrap();
        let tar = tar_with_a_large_file(1 << 20);
        let xz = xz_bytes(&tar);
        let place = |path: &Path| inside(path, 1);
        // Cut inside the large file.
        let error = unpack_tar_xz(&xz[..xz.len() / 2], &root, place).unwrap_err();
        assert!(error.starts_with("xz: "), "{error}");
        // A flipped bit in the middle fails the block's check or its data.
        let mut flipped = xz.clone();
        flipped[xz.len() / 2] ^= 0x40;
        assert!(unpack_tar_xz(&flipped[..], &root, place).is_err());
        // A damaged footer is found after the tar has ended.
        let mut footer = xz.clone();
        let last = footer.len() - 1;
        footer[last] ^= 0xff;
        let error = unpack_tar_xz(&footer[..], &root, place).unwrap_err();
        assert!(error.starts_with("xz: "), "{error}");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_debian_package_data_member_is_unpacked_from_the_file() {
        let root =
            std::env::temp_dir().join(format!("ant-tools-deb-{}", crate::storage::unique_id()));
        fs::create_dir_all(&root).unwrap();
        let mut builder = tar::Builder::new(Vec::new());
        let body = b"library";
        let mut header = tar::Header::new_gnu();
        header.set_size(body.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "usr/lib/libicu-test.so", &body[..])
            .unwrap();
        builder
            .append_data(&mut header, "usr/share/other", &body[..])
            .unwrap();
        let data = xz_bytes(&builder.into_inner().unwrap());
        let mut deb = b"!<arch>\n".to_vec();
        // An odd-sized member before the data is padded to an even offset.
        for (name, content) in [
            ("debian-binary", &b"2.0\n"[..]),
            ("odd", b"123"),
            ("data.tar.xz", &data),
        ] {
            deb.extend(
                format!(
                    "{name:<16}{:<12}0     0     100644  {:<10}`\n",
                    0,
                    content.len()
                )
                .bytes(),
            );
            deb.extend(content);
            if content.len() % 2 == 1 {
                deb.push(b'\n');
            }
        }
        let archive = root.join("lib.deb");
        fs::write(&archive, &deb).unwrap();
        let download = Download {
            file: "lib.deb",
            url: "https://example.invalid/lib.deb",
            sha256: "",
            size: 0,
            archive: Archive::DebFiles { prefix: "usr/lib/" },
            into: "base",
        };
        let target = root.join("out");
        unpack(&download, &archive, &target).unwrap();
        assert_eq!(fs::read(target.join("base/libicu-test.so")).unwrap(), body);
        assert!(!target.join("base/other").exists());
        fs::write(&archive, &deb[..deb.len() - 20]).unwrap();
        assert!(unpack(&download, &archive, &target).is_err());
        fs::write(&archive, b"!<arch>\nnot an archive").unwrap();
        assert!(unpack(&download, &archive, &target).is_err());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_tar_xz_download_unpacks_without_its_top_directory() {
        let root =
            std::env::temp_dir().join(format!("ant-tools-xz-{}", crate::storage::unique_id()));
        fs::create_dir_all(&root).unwrap();
        let mut builder = tar::Builder::new(Vec::new());
        let body = b"#!/bin/sh\n";
        let mut header = tar::Header::new_gnu();
        header.set_size(body.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        builder
            .append_data(
                &mut header,
                "magika-cli-x86_64-unknown-linux-gnu/magika",
                &body[..],
            )
            .unwrap();
        let tar = builder.into_inner().unwrap();
        let xz = xz_bytes(&tar);
        let archive = root.join("magika.tar.xz");
        fs::write(&archive, &xz).unwrap();
        let download = Download {
            file: "magika.tar.xz",
            url: "https://example.invalid/magika.tar.xz",
            sha256: "",
            size: 0,
            archive: Archive::TarXz { strip: 1 },
            into: "",
        };
        let target = root.join("out");
        unpack(&download, &archive, &target).unwrap();
        assert_eq!(fs::read(target.join("magika")).unwrap(), body);
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(target.join("magika"))
                .unwrap()
                .permissions()
                .mode()
                & 0o111,
            0o111
        );
        fs::write(&archive, b"not an xz stream").unwrap();
        assert!(unpack(&download, &archive, &target).is_err());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn the_debugger_consoles_are_pinned_to_the_upstream_files_they_were_checked_against() {
        let gef = package("gef").unwrap();
        let [download] = gef.downloads else {
            panic!("one GEF download");
        };
        // The commit in the URL is the version, and the file is a single script.
        assert!(download.url.contains("/bata24/gef/fc085a60be33"));
        assert!(gef.version.contains("fc085a6"));
        assert!(download.url.ends_with("/gef.py"));
        assert_eq!(
            download.sha256,
            "fabcdc13c8c7a81ceaa2af891f6ce4695d623adef98c8f2ccf365bbbf4df90ce"
        );
        assert!(matches!(download.archive, Archive::File));
        assert_eq!(gef.entry, "gef.py");
        assert!(gef.license.starts_with("MIT"));
        assert!(system_candidates("gef").is_empty());

        let pwndbg = package("pwndbg").unwrap();
        let [download] = pwndbg.downloads else {
            panic!("one pwndbg download");
        };
        assert_eq!(
            download.url,
            format!(
                "https://github.com/pwndbg/pwndbg/releases/download/{0}/pwndbg_{0}_x86_64-portable.tar.xz",
                pwndbg.version
            )
        );
        assert_eq!(
            download.sha256,
            "7ba64666ee595885ba4b0e073f85e423829103e9fdbe921ba4eef1acd9150803"
        );
        assert!(matches!(download.archive, Archive::TarXz { strip: 1 }));
        assert_eq!(pwndbg.entry, "bin/pwndbg");
        assert!(pwndbg.license.starts_with("MIT"));
        assert!(
            system_candidates("pwndbg")
                .iter()
                .all(|path| path.ends_with("/pwndbg"))
        );
    }

    #[test]
    fn the_notices_name_the_debugger_consoles_with_the_pinned_hashes_and_terms() {
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../../THIRD-PARTY-NOTICES.md");
        // A source package without the repository's top level has no file.
        let Ok(notices) = fs::read_to_string(path) else {
            return;
        };
        for id in ["gef", "pwndbg"] {
            let package = package(id).unwrap();
            for download in package.downloads {
                assert!(notices.contains(download.sha256), "{id} hash");
            }
            assert!(notices.contains("MIT"), "{id} terms");
        }
        assert!(notices.contains("fc085a60be334d38d498296187344e9e7d558587"));
        assert!(notices.contains("Copyright (c) 2021-2026 bata24"));
        assert!(notices.contains("pwndbg 2026.09.15"));
        assert!(notices.contains("Copyright (c) 2026 Dominik 'Disconnect3d' Czarnota"));
        assert!(notices.contains("GDB 17.2 (GPL-3.0-or-later)"));
    }

    #[test]
    fn a_single_file_download_is_kept_under_its_name_read_only() {
        let root =
            std::env::temp_dir().join(format!("ant-tools-file-{}", crate::storage::unique_id()));
        fs::create_dir_all(&root).unwrap();
        let archive = root.join("gef.py");
        fs::write(&archive, b"print('gef')\n").unwrap();
        let download = Download {
            file: "gef.py",
            url: "https://example.invalid/gef.py",
            sha256: "",
            size: 0,
            archive: Archive::File,
            into: "",
        };
        let target = root.join("out");
        unpack(&download, &archive, &target).unwrap();
        assert_eq!(fs::read(target.join("gef.py")).unwrap(), b"print('gef')\n");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(target.join("gef.py"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o444
        );
        let _ = fs::remove_dir_all(&root);
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
