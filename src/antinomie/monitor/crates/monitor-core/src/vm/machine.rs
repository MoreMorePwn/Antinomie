// SPDX-License-Identifier: GPL-3.0-only
//! The machine each guest architecture runs on and where QEMU maps its RAM.
use std::path::{Path, PathBuf};

/// The machine a guest architecture runs on. x86-64: q35 (or i440FX, which
/// lays RAM out the same below 0xb0000000 bytes) with `qemu-system-x86_64`;
/// arm64: `virt` with `qemu-system-aarch64`, under TCG (MA-09: direct kernel
/// boot with a device tree, or AAVMF with ACPI).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Machine {
    Pc,
    Virt,
}
/// How many times longer an arm64 guest takes than an x86-64 one under KVM
/// (TCG, measured in MA-09: 6 to 10 times for exec- and system-call-heavy
/// work): host deadlines that are wall-clock based scale by it. The one place
/// it is set; scripts/vm-regress.py reads it from here.
pub(crate) const ARM64_TIME_SCALE: u32 = 8;
/// Where `virt` maps guest RAM.
pub(crate) const VIRT_RAM_BASE: u64 = 0x4000_0000;
/// The least RAM an arm64 VM gets: below it, QEMU's initrd or the firmware's
/// top-down allocations reach the bootstrap page at the middle of RAM.
pub(crate) const VIRT_MIN_RAM_MIB: u32 = 512;
impl Machine {
    /// The machine of a base's architecture, or why there is none.
    pub fn of(arch: crate::api::GuestArch) -> Result<Self, String> {
        match arch {
            crate::api::GuestArch::X86_64 => Ok(Self::Pc),
            crate::api::GuestArch::AARCH64 => Ok(Self::Virt),
            other => Err(format!(
                "this Antinomie has no virtual machine for {} guests",
                other.label()
            )),
        }
    }
    /// The QEMU program: the configured one for x86-64, and for arm64 the
    /// `qemu-system-aarch64` beside it (or on PATH).
    pub fn qemu(self, configured: &Path) -> PathBuf {
        match self {
            Self::Pc => configured.to_path_buf(),
            Self::Virt => match configured.parent() {
                Some(dir)
                    if configured
                        .file_name()
                        .is_some_and(|name| name.to_string_lossy().starts_with("qemu-system-"))
                        && !dir.as_os_str().is_empty() =>
                {
                    dir.join("qemu-system-aarch64")
                }
                _ => PathBuf::from("qemu-system-aarch64"),
            },
        }
    }
    pub fn ram_layout(self, ram_size: u64) -> RamLayout {
        match self {
            Self::Pc => RamLayout::q35(ram_size),
            Self::Virt => RamLayout::virt(ram_size),
        }
    }
    /// Whether a VM of this many MiB can boot on the machine.
    pub fn check_ram(self, ram_mib: u32) -> Result<(), String> {
        if self == Self::Virt && ram_mib < VIRT_MIN_RAM_MIB {
            return Err(format!(
                "an arm64 VM needs at least {VIRT_MIN_RAM_MIB} MiB of RAM; this one has {ram_mib} MiB"
            ));
        }
        Ok(())
    }
    /// The guest's serial console device.
    pub fn console(self) -> &'static str {
        match self {
            Self::Pc => "ttyS0",
            Self::Virt => "ttyAMA0",
        }
    }
    /// Unused until MA-16 starts arm64 VMs and scales their deadlines.
    #[allow(dead_code)]
    pub fn time_scale(self) -> u32 {
        match self {
            Self::Pc => 1,
            Self::Virt => ARM64_TIME_SCALE,
        }
    }
    /// What a full snapshot records of the machine (x86-64: what it always did).
    pub fn identity(self, pc_machine: &str) -> String {
        match self {
            Self::Pc => format!("{pc_machine},max-ram-below-4g=4G"),
            Self::Virt => "virt,gic-version=3 qemu-system-aarch64".into(),
        }
    }
}

/// Guest RAM as QEMU lays it out, from one backing file. q35: QEMU keeps
/// 0xb0000000 bytes below 4 GiB, or only 2 GiB once RAM reaches that size,
/// and places the rest at 4 GiB, the high part of the file directly after the
/// low. `virt`: all RAM in one piece at `base` (1 GiB).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RamLayout {
    pub base: u64,
    pub low: u64,
    pub high: u64,
}
pub(crate) const HIGH_RAM_GPA: u64 = 1 << 32;
impl RamLayout {
    pub fn q35(ram_size: u64) -> Self {
        let lowmem = if ram_size >= 0xb000_0000 {
            0x8000_0000
        } else {
            0xb000_0000
        };
        let low = ram_size.min(lowmem);
        Self {
            base: 0,
            low,
            high: ram_size - low,
        }
    }
    pub fn virt(ram_size: u64) -> Self {
        Self {
            base: VIRT_RAM_BASE,
            low: ram_size,
            high: 0,
        }
    }
    pub fn size(&self) -> u64 {
        self.low + self.high
    }
    /// The bootstrap page when the options name none: page aligned in the
    /// middle of the first piece of RAM (MA-09: clear of what QEMU and the
    /// firmware place, on q35 and on virt).
    pub fn default_bootstrap(&self) -> u64 {
        self.base + ((self.low / 2) & !4095)
    }
    /// Whether a page at `gpa` lies inside the first piece of RAM, and not in
    /// the first MiB.
    pub fn bootstrap_fits(&self, gpa: u64) -> bool {
        gpa >= self.base + 0x100000
            && gpa.is_multiple_of(4096)
            && gpa
                .checked_add(4096)
                .is_some_and(|end| end <= self.base + self.low)
    }
    /// `virt`'s RAM in `info mtree -f`: the backend region itself at its
    /// address (`40000000-7fffffff (prio 0, ram): shared`), as (GPA, size,
    /// backing offset) triples.
    pub(super) fn from_flat_mtree(mtree: &str) -> Result<Vec<(u64, u64, u64)>, String> {
        let mut found = Vec::new();
        for line in mtree.lines() {
            let Some((range, rest)) = line.split_once(" (prio ") else {
                continue;
            };
            if !rest.ends_with("ram): shared") {
                continue;
            }
            let (start, end) = range
                .trim()
                .split_once('-')
                .ok_or("unreadable QEMU memory map")?;
            let start = u64::from_str_radix(start, 16).map_err(|_| "unreadable QEMU memory map")?;
            let end = u64::from_str_radix(end, 16).map_err(|_| "unreadable QEMU memory map")?;
            let region = (start, end - start + 1, 0);
            if !found.contains(&region) {
                found.push(region);
            }
        }
        found.sort_unstable();
        Ok(found)
    }
    /// Reads QEMU's `ram-below-4g`/`ram-above-4g` aliases from `info mtree`
    /// output as (GPA, size, backing offset) triples.
    pub(super) fn from_mtree(mtree: &str) -> Result<Vec<(u64, u64, u64)>, String> {
        let parse = |range: &str| -> Option<(u64, u64)> {
            let (start, end) = range.trim().split_once('-')?;
            let start = u64::from_str_radix(start, 16).ok()?;
            let end = u64::from_str_radix(end.split_whitespace().next()?, 16).ok()?;
            Some((start, end.checked_sub(start)?.checked_add(1)?))
        };
        let mut found = Vec::new();
        for line in mtree.lines() {
            let Some((range, alias)) = line.split_once(" (prio ") else {
                continue;
            };
            let Some((_, target)) = alias
                .split_once("alias ram-below-4g @")
                .or_else(|| alias.split_once("alias ram-above-4g @"))
            else {
                continue;
            };
            let (gpa, size) = parse(range).ok_or("unreadable QEMU memory map")?;
            let (offset, alias_size) = target
                .split_once(' ')
                .and_then(|(_, range)| parse(range))
                .ok_or("unreadable QEMU memory map")?;
            if alias_size != size {
                return Err("unreadable QEMU memory map".into());
            }
            if !found.contains(&(gpa, size, offset)) {
                found.push((gpa, size, offset));
            }
        }
        found.sort_unstable();
        Ok(found)
    }
    /// Where each piece of RAM is: (GPA, size, offset in the backing file).
    pub fn expected(&self) -> Vec<(u64, u64, u64)> {
        let mut regions = vec![(self.base, self.low, 0)];
        if self.high != 0 {
            regions.push((HIGH_RAM_GPA, self.high, self.low));
        }
        regions
    }
}
