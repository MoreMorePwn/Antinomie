// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! The schema set of each architecture the host ships (`protocol/<arch>/`):
//! its native syscall table, its captured layouts and its constants file.
//!
//! The decoding tables in this crate carry x86-64 values. A constants file
//! (`scripts/generate-arch-constants.py`) lists where another architecture's
//! value of a named constant differs, which names it lacks and which arch-only
//! names a group gains, so one table serves every architecture by name.
use super::Abi;
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap, HashSet};

/// The C data model of an architecture's native ABI.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
pub enum DataModel {
    /// `long` and pointers are 64 bits (x86-64, aarch64, riscv64).
    #[serde(rename = "LP64")]
    Lp64,
    /// `int`, `long` and pointers are 32 bits (arm EABI, mips o32).
    #[serde(rename = "ILP32")]
    Ilp32,
}

/// Byte order of the guest's native data (captured layouts, user memory).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Endian {
    Little,
    Big,
}

/// One architecture's identity and constant differences from x86-64.
#[derive(Debug, Deserialize)]
pub struct Constants {
    pub architecture: String,
    /// ELF `e_machine` of the architecture's programs and cores.
    pub elf_machine: u16,
    /// ELF class: 32 or 64.
    pub elf_class: u8,
    pub endianness: Endian,
    pub data_model: DataModel,
    /// `AUDIT_ARCH_*` as auditd prints it (`arch=c00000b7`).
    pub audit_arch: String,
    /// Prefix of the layout names the guest records (`linux-6.12.94/aarch64/`).
    pub layout_prefix: String,
    changed: HashMap<String, i64>,
    absent: HashSet<String>,
    additions: HashMap<String, BTreeMap<String, i64>>,
}

impl Constants {
    /// This architecture's value of a constant whose x86-64 value is
    /// `generic`, or None when the architecture does not define the name.
    pub fn value(&self, name: &str, generic: u64) -> Option<u64> {
        if self.absent.contains(name) {
            return None;
        }
        // Values are stored as C evaluates them; a negative one is the same
        // bit pattern the 64-bit argument carries.
        Some(
            self.changed
                .get(name)
                .map_or(generic, |&value| value as u64),
        )
    }

    /// Names only this architecture defines, for a host group (`protection`,
    /// `ptrace_request`).
    pub fn additions(&self, group: &str) -> impl Iterator<Item = (&str, u64)> {
        self.additions
            .get(group)
            .into_iter()
            .flatten()
            .map(|(name, &value)| (name.as_str(), value as u64))
    }

    /// Size of a C `long` (and of a pointer) in bytes.
    pub fn long_size(&self) -> usize {
        match self.data_model {
            DataModel::Lp64 => 8,
            DataModel::Ilp32 => 4,
        }
    }
}

/// The compiled-in schema files of an ABI. Generated, validated by the tests
/// and the generators' `--check` modes.
pub(super) fn native_syscalls_json(abi: Abi) -> &'static str {
    match abi {
        Abi::X86_64 => include_str!("../../../../protocol/x86_64/native-syscalls.json"),
        Abi::Aarch64 => include_str!("../../../../protocol/aarch64/native-syscalls.json"),
    }
}

fn constants_json(abi: Abi) -> &'static str {
    match abi {
        Abi::X86_64 => include_str!("../../../../protocol/x86_64/constants.json"),
        Abi::Aarch64 => include_str!("../../../../protocol/aarch64/constants.json"),
    }
}

/// The captured-layout inventory of an ABI (`captured-layout-members.json`).
pub fn captured_layouts_json(abi: Abi) -> &'static str {
    match abi {
        Abi::X86_64 => include_str!("../../../../protocol/x86_64/captured-layout-members.json"),
        Abi::Aarch64 => include_str!("../../../../protocol/aarch64/captured-layout-members.json"),
    }
}

pub(super) fn load_constants(abi: Abi) -> Constants {
    serde_json::from_str(constants_json(abi)).expect("invalid compiled architecture constants")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_set_names_its_architecture_and_layout_prefix() {
        for (abi, name, machine) in [(Abi::X86_64, "x86_64", 62), (Abi::Aarch64, "aarch64", 183)] {
            let constants = load_constants(abi);
            assert_eq!(constants.architecture, name);
            assert_eq!(constants.elf_machine, machine);
            assert_eq!(constants.elf_class, 64);
            assert_eq!(constants.endianness, Endian::Little);
            assert_eq!(constants.data_model, DataModel::Lp64);
            assert_eq!(constants.layout_prefix, format!("linux-6.12.94/{name}/"));
            let layouts: serde_json::Value =
                serde_json::from_str(captured_layouts_json(abi)).unwrap();
            assert_eq!(layouts["architecture"], name);
            let table: serde_json::Value = serde_json::from_str(native_syscalls_json(abi)).unwrap();
            assert_eq!(table["architecture"], name);
            for layout in layouts["layouts"].as_array().unwrap() {
                let layout = layout["layout"].as_str().unwrap();
                assert!(layout.starts_with(&constants.layout_prefix), "{layout}");
            }
        }
    }

    #[test]
    fn x86_64_is_the_base_of_every_difference() {
        let x86 = load_constants(Abi::X86_64);
        assert!(x86.changed.is_empty() && x86.absent.is_empty() && x86.additions.is_empty());
        assert_eq!(x86.value("O_DIRECTORY", 0o200000), Some(0o200000));
        assert_eq!(x86.audit_arch, "c000003e");
    }

    #[test]
    fn aarch64_differs_where_its_uapi_does() {
        let arm = load_constants(Abi::Aarch64);
        assert_eq!(arm.audit_arch, "c00000b7");
        // asm-generic/fcntl.h vs arch/arm64/include/uapi/asm/fcntl.h
        assert_eq!(arm.value("O_DIRECTORY", 0o200000), Some(0o40000));
        assert_eq!(arm.value("O_NOFOLLOW", 0o400000), Some(0o100000));
        assert_eq!(arm.value("O_DIRECT", 0o40000), Some(0o200000));
        assert_eq!(arm.value("O_LARGEFILE", 0o100000), Some(0o400000));
        assert_eq!(arm.value("O_CREAT", 0o100), Some(0o100));
        assert_eq!(arm.value("MAP_32BIT", 0x40), None);
        assert_eq!(arm.value("ARCH_SET_FS", 0x1002), None);
        let protection: Vec<_> = arm.additions("protection").collect();
        assert_eq!(protection, [("PROT_BTI", 0x10), ("PROT_MTE", 0x20)]);
        assert_eq!(arm.additions("open").count(), 0);
    }
}
