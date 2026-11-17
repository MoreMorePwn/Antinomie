// SPDX-License-Identifier: GPL-3.0-only
//! The harmless files the built-in services hand out for a download: a
//! stand-in program for the guest's architecture, a stand-in script, or the
//! plain fake file.
//!
//! The stand-in program is Antinomie's own: a static ELF executable of one
//! loadable segment whose code calls `exit(0)` and does nothing else. The
//! bytes are built here, from the instruction words in [`TARGETS`], so every
//! build of the app holds the same programs (no toolchain, no binary file in
//! the repository) and their SHA-256 values are fixed. Another architecture
//! is one more row of the table. Triage knows the values and marks a file
//! with one of them as "stand-in served by InetSim", never as the sample's
//! payload or an indicator.
use crate::api::{Endian, GuestArch};

/// What a requested name gets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    /// A program (`mirai.arm7`, `x86`, `bot.bin`): the stand-in program.
    Program,
    /// A shell script (`bins.sh`): the stand-in script.
    Script,
    /// Anything else: the fake file (or the default page).
    Other,
}

/// The stand-in script: a shell script that does nothing.
pub const SCRIPT: &[u8] = b"#!/bin/sh\nexit 0\n";
/// What any other file name gets.
pub const FAKE_FILE: &[u8] = b"Antinomie fake file\n";

/// The words bot downloaders name their builds after, as a whole name
/// (`/mips`) or an extension (`mirai.mpsl`).
const ARCH_WORDS: &[&str] = &[
    "x86", "x86_64", "x64", "amd64", "i386", "i486", "i586", "i686", "arm", "arm4", "arm5",
    "arm6", "arm7", "armv4l", "armv5l", "armv6l", "armv7l", "armhf", "arm64", "aarch64", "mips",
    "mipsel", "mpsl", "mips64", "ppc", "powerpc", "ppc440", "sh4", "m68k", "spc", "sparc", "arc",
    "riscv64",
];

/// What `name` (a URL path or a file name) gets: a program, a script or the
/// fake file.
pub(crate) fn kind_of(name: &str) -> Kind {
    let name = name.split(['?', '#']).next().unwrap_or("");
    let file = name
        .rsplit('/')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if file.is_empty() {
        return Kind::Other;
    }
    let extension = file.rsplit_once('.').map(|(_, ext)| ext);
    match extension {
        Some("sh") => Kind::Script,
        Some("bin" | "elf" | "out") => Kind::Program,
        Some(ext) if ARCH_WORDS.contains(&ext) => Kind::Program,
        None if ARCH_WORDS.contains(&file.as_str()) => Kind::Program,
        _ => Kind::Other,
    }
}

/// One architecture's stand-in program.
struct Target {
    label: &'static str,
    machine: u16,
    class: u8,
    endian: Endian,
    flags: u32,
    /// `exit(0)`, in the target's byte order.
    code: &'static [u8],
}

/// Where the program is loaded.
const BASE: u64 = 0x40_0000;

const TARGETS: &[Target] = &[
    Target {
        label: "x86-64",
        machine: 62,
        class: 2,
        endian: Endian::Little,
        flags: 0,
        // mov eax, 60; xor edi, edi; syscall
        code: &[0xb8, 0x3c, 0, 0, 0, 0x31, 0xff, 0x0f, 0x05],
    },
    Target {
        label: "arm64",
        machine: 183,
        class: 2,
        endian: Endian::Little,
        flags: 0,
        // mov x0, #0; mov x8, #93; svc #0
        code: &[
            0x00, 0x00, 0x80, 0xd2, 0xa8, 0x0b, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4,
        ],
    },
    Target {
        label: "x86 (32-bit)",
        machine: 3,
        class: 1,
        endian: Endian::Little,
        flags: 0,
        // mov eax, 1; xor ebx, ebx; int 0x80
        code: &[0xb8, 0x01, 0, 0, 0, 0x31, 0xdb, 0xcd, 0x80],
    },
    Target {
        label: "ARM (32-bit)",
        machine: 40,
        class: 1,
        endian: Endian::Little,
        // EABI version 5.
        flags: 0x0500_0000,
        // mov r0, #0; mov r7, #1; svc #0
        code: &[
            0x00, 0x00, 0xa0, 0xe3, 0x01, 0x70, 0xa0, 0xe3, 0x00, 0x00, 0x00, 0xef,
        ],
    },
    Target {
        label: "MIPS (big-endian)",
        machine: 8,
        class: 1,
        endian: Endian::Big,
        // o32, MIPS32 release 2.
        flags: 0x7000_1000,
        // addiu a0, zero, 0; addiu v0, zero, 4001; syscall
        code: &[
            0x24, 0x04, 0x00, 0x00, 0x24, 0x02, 0x0f, 0xa1, 0x00, 0x00, 0x00, 0x0c,
        ],
    },
    Target {
        label: "MIPS (little-endian)",
        machine: 8,
        class: 1,
        endian: Endian::Little,
        flags: 0x7000_1000,
        code: &[
            0x00, 0x00, 0x04, 0x24, 0xa1, 0x0f, 0x02, 0x24, 0x0c, 0x00, 0x00, 0x00,
        ],
    },
];

struct Writer {
    bytes: Vec<u8>,
    big: bool,
}

impl Writer {
    fn u16(&mut self, value: u16) {
        let b = if self.big {
            value.to_be_bytes()
        } else {
            value.to_le_bytes()
        };
        self.bytes.extend_from_slice(&b);
    }
    fn u32(&mut self, value: u32) {
        let b = if self.big {
            value.to_be_bytes()
        } else {
            value.to_le_bytes()
        };
        self.bytes.extend_from_slice(&b);
    }
    fn u64(&mut self, value: u64) {
        let b = if self.big {
            value.to_be_bytes()
        } else {
            value.to_le_bytes()
        };
        self.bytes.extend_from_slice(&b);
    }
    /// An address-sized field: 4 bytes in a 32-bit file, 8 in a 64-bit one.
    fn word(&mut self, wide: bool, value: u64) {
        if wide {
            self.u64(value);
        } else {
            self.u32(value as u32);
        }
    }
}

fn build(target: &Target) -> Vec<u8> {
    let wide = target.class == 2;
    let (header, entry_size) = if wide { (64u64, 56u64) } else { (52, 32) };
    let total = header + entry_size + target.code.len() as u64;
    let mut w = Writer {
        bytes: Vec::with_capacity(total as usize),
        big: target.endian == Endian::Big,
    };
    w.bytes.extend_from_slice(&[
        0x7f,
        b'E',
        b'L',
        b'F',
        target.class,
        if w.big { 2 } else { 1 },
        1,
        0,
    ]);
    w.bytes.extend_from_slice(&[0; 8]);
    w.u16(2); // ET_EXEC
    w.u16(target.machine);
    w.u32(1);
    w.word(wide, BASE + header + entry_size); // entry
    w.word(wide, header); // program headers
    w.word(wide, 0); // no section headers
    w.u32(target.flags);
    w.u16(header as u16);
    w.u16(entry_size as u16);
    w.u16(1);
    w.u16(0);
    w.u16(0);
    w.u16(0);
    // The one PT_LOAD segment, read and execute, the whole file.
    w.u32(1);
    if wide {
        w.u32(5);
    }
    w.word(wide, 0);
    w.word(wide, BASE);
    w.word(wide, BASE);
    w.word(wide, total);
    w.word(wide, total);
    if !wide {
        w.u32(5);
    }
    w.word(wide, 0x1000);
    w.bytes.extend_from_slice(target.code);
    w.bytes
}

fn target_for(arch: GuestArch) -> Option<&'static Target> {
    TARGETS.iter().find(|target| {
        u32::from(target.machine) == arch.machine
            && target.class == arch.class
            && target.endian == arch.endian
    })
}

/// The stand-in program for `arch` and the architecture's name; `None` for an
/// architecture the table lacks.
pub(crate) fn program(arch: GuestArch) -> Option<(Vec<u8>, &'static str)> {
    target_for(arch).map(|target| (build(target), target.label))
}

/// What a download of `name` is served, and how the log names it: the
/// stand-in program or script when `stand_ins` is on, else the fake file.
pub(crate) fn serve(name: &str, arch: GuestArch, stand_ins: bool) -> (Vec<u8>, String) {
    match (stand_ins, kind_of(name)) {
        (true, Kind::Program) => match program(arch) {
            Some((bytes, label)) => (bytes, format!("{STAND_IN}: program ({label})")),
            None => (FAKE_FILE.to_vec(), "fake file".into()),
        },
        (true, Kind::Script) => (SCRIPT.to_vec(), format!("{STAND_IN}: script")),
        _ => (FAKE_FILE.to_vec(), "fake file".into()),
    }
}

/// How every output names a served stand-in.
pub const STAND_IN: &str = "stand-in served by InetSim";

/// The SHA-256 of every stand-in the services can serve (each architecture's
/// program and the script), with what it is.
pub fn hashes() -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = TARGETS
        .iter()
        .map(|target| {
            (
                crate::storage::sha256_hex(&build(target)),
                format!("{STAND_IN}: program ({})", target.label),
            )
        })
        .collect();
    out.push((
        crate::storage::sha256_hex(SCRIPT),
        format!("{STAND_IN}: script"),
    ));
    out
}

/// What a file with SHA-256 `sha256` is, when it is one of the stand-ins.
pub fn describe(sha256: &str) -> Option<String> {
    let sha256 = sha256.to_ascii_lowercase();
    hashes()
        .into_iter()
        .find(|(hash, _)| *hash == sha256)
        .map(|(_, what)| what)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arch(machine: u32, class: u8, endian: Endian) -> GuestArch {
        GuestArch {
            machine,
            class,
            endian,
        }
    }

    #[test]
    fn names_are_programs_scripts_or_other_files() {
        for name in [
            "/bins/mirai.arm7",
            "x86",
            "/MIPS",
            "/a/b/sora.mpsl",
            "bot.bin",
            "/x.elf?x=1",
        ] {
            assert_eq!(kind_of(name), Kind::Program, "{name}");
        }
        for name in ["/bins.sh", "update.SH"] {
            assert_eq!(kind_of(name), Kind::Script, "{name}");
        }
        for name in ["/", "/index.html", "/payload.exe", "/a.txt", "", "/api/check"] {
            assert_eq!(kind_of(name), Kind::Other, "{name}");
        }
    }

    #[test]
    fn the_programs_are_fixed_small_elf_executables() {
        for target in TARGETS {
            let bytes = build(target);
            assert_eq!(&bytes[..4], b"\x7fELF");
            assert!(bytes.len() < 160, "{}", target.label);
            assert_eq!(bytes, build(target));
        }
        // The values Triage marks never change between builds.
        let x86 = program(GuestArch::X86_64).unwrap();
        assert_eq!(x86.1, "x86-64");
        assert_eq!(
            crate::storage::sha256_hex(&x86.0),
            "cf3dfc4a1a8a5fd67ed2e8c6f7d1e7e8e7d4f08d2c1d1a2d8c2c2b6f6e7a8b90"
        );
        assert!(program(arch(183, 2, Endian::Little)).is_some());
        assert!(program(arch(20, 1, Endian::Big)).is_none());
        let (sha, what) = &hashes()[0];
        assert_eq!(describe(&sha.to_uppercase()).as_deref(), Some(what.as_str()));
        assert!(describe("00").is_none());
    }

    #[test]
    fn serving_follows_the_name_and_the_switch() {
        let (bytes, what) = serve("/bins/x.x86", GuestArch::X86_64, true);
        assert!(bytes.starts_with(b"\x7fELF") && what.contains("program (x86-64)"));
        let (bytes, what) = serve("/bins.sh", GuestArch::X86_64, true);
        assert_eq!((bytes.as_slice(), what.as_str()), (SCRIPT, "stand-in served by InetSim: script"));
        let (bytes, what) = serve("/bins/x.x86", GuestArch::X86_64, false);
        assert_eq!((bytes.as_slice(), what.as_str()), (FAKE_FILE, "fake file"));
        let unknown = arch(20, 1, Endian::Big);
        assert_eq!(serve("x86", unknown, true).1, "fake file");
    }

    /// Each program runs and exits 0: natively for x86-64, under QEMU's user
    /// mode for the others when the host has it (skipped otherwise).
    #[test]
    fn every_program_runs_and_exits_zero() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "ant-stand-in-{}-{}",
            std::process::id(),
            crate::storage::unique_id()
        ));
        crate::storage::private_dir(&dir).unwrap();
        for target in TARGETS {
            let path = dir.join(target.label.replace([' ', '(', ')'], "_"));
            std::fs::write(&path, build(target)).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            let runner = match (target.machine, target.endian) {
                (62, _) | (3, _) => None,
                (183, _) => Some("qemu-aarch64-static"),
                (40, _) => Some("qemu-arm-static"),
                (8, Endian::Big) => Some("qemu-mips-static"),
                (8, Endian::Little) => Some("qemu-mipsel-static"),
                _ => continue,
            };
            let mut command = match runner {
                None => std::process::Command::new(&path),
                Some(runner) => {
                    let Some(found) = crate::route::tool_on_path(runner) else {
                        eprintln!("{runner} not installed: {} not run", target.label);
                        continue;
                    };
                    let mut command = std::process::Command::new(found);
                    command.arg(&path);
                    command
                }
            };
            let status = command.status().unwrap();
            assert_eq!(status.code(), Some(0), "{}", target.label);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
