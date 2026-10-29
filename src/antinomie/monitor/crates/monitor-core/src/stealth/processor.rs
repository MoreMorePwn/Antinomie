// SPDX-License-Identifier: GPL-3.0-only
//! The processor (SMBIOS type 4) and its caches (type 7), written whole as a
//! PC's firmware does. QEMU's own `-smbios type=4` numbers the socket after
//! the designation ("U3E1 0"), gives the CPU a made-up voltage, external
//! clock and upgrade, and leaves the cache handles unset.
use super::{MachineIdentity, host_cpu_vendor, host_cpuinfo, launch, smbios};

/// The handle QEMU gives its first processor, and the first cache table.
const PROCESSOR_HANDLE: u16 = 0x0400;
const CACHE_HANDLE: u16 = 0x0700;

/// A cache level as the host's CPU reports it, for one core.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Cache {
    pub level: u8,
    /// SMBIOS system cache type: 3 instruction, 4 data, 5 unified.
    pub kind: u8,
    pub kib: u32,
    pub ways: u32,
}

/// What the type 4 table is written from.
pub(super) struct Processor {
    pub socket: String,
    pub manufacturer: String,
    pub brand: String,
    pub part: String,
    /// CPUID leaf 1 EAX and EDX.
    pub signature: (u32, u32),
    pub family: u16,
    pub max_mhz: u16,
    pub current_mhz: u16,
    pub upgrade: u8,
    /// In tenths of a volt.
    pub voltage: u8,
    pub cores: u16,
    pub threads: u16,
    pub characteristics: u16,
    /// The host's caches per core; the L3 is shared.
    pub caches: Vec<Cache>,
}

/// CPUID leaf 1 EAX from the display family, model and stepping of
/// /proc/cpuinfo (the base values plus the extended ones).
pub(super) fn signature_eax(family: u32, model: u32, stepping: u32) -> u32 {
    let (base_family, extended_family) = if family >= 0xf {
        (0xf, family - 0xf)
    } else {
        (family, 0)
    };
    let extended_model = if family == 6 || family >= 0xf {
        model >> 4
    } else {
        0
    };
    (extended_family << 20)
        | (extended_model << 16)
        | (base_family << 8)
        | ((model & 0xf) << 4)
        | (stepping & 0xf)
}

/// The SMBIOS associativity code of a cache with `ways` ways.
fn associativity(ways: u32) -> u8 {
    match ways {
        1 => 0x03,
        2 => 0x04,
        4 => 0x05,
        8 => 0x07,
        16 => 0x08,
        12 => 0x09,
        24 => 0x0a,
        32 => 0x0b,
        48 => 0x0c,
        64 => 0x0d,
        20 => 0x0e,
        _ => 0x02,
    }
}

/// The cache sizes in KiB of a sysfs `size` value ("32K", "16384K", "1M").
pub(super) fn cache_kib(text: &str) -> Option<u32> {
    let text = text.trim();
    if let Some(kib) = text.strip_suffix('K') {
        kib.parse().ok()
    } else {
        text.strip_suffix('M')?
            .parse::<u32>()
            .ok()
            .map(|mib| mib * 1024)
    }
}

/// The caches of the host's first CPU.
pub(super) fn host_caches() -> Vec<Cache> {
    let read = |index: u32, name: &str| {
        std::fs::read_to_string(format!(
            "/sys/devices/system/cpu/cpu0/cache/index{index}/{name}"
        ))
        .ok()
        .map(|text| text.trim().to_owned())
    };
    (0..8)
        .map_while(|index| {
            let level = read(index, "level")?.parse().ok()?;
            let kind = match read(index, "type")?.as_str() {
                "Instruction" => 3,
                "Data" => 4,
                _ => 5,
            };
            Some(Cache {
                level,
                kind,
                kib: cache_kib(&read(index, "size")?)?,
                ways: read(index, "ways_of_associativity")
                    .and_then(|ways| ways.parse().ok())
                    .unwrap_or(0),
            })
        })
        .collect()
}

/// The characteristics bits a CPU of the host's features has: 64-bit capable,
/// multi-core, hardware thread, execute protection, enhanced virtualization
/// and power/performance control, as PC firmware reports them.
pub(super) fn characteristics(cores: u16, threads: u16, flags: &str) -> u16 {
    let has = |flag: &str| flags.split_whitespace().any(|name| name == flag);
    let mut bits = 0u16;
    if has("lm") {
        bits |= 1 << 2;
    }
    if cores > 1 {
        bits |= 1 << 3;
    }
    if threads > cores {
        bits |= 1 << 4;
    }
    if has("nx") {
        bits |= 1 << 5;
    }
    if has("vmx") || has("svm") {
        bits |= 1 << 6;
    }
    // Speed stepping or the AMD equivalent (cpb, hwp, est).
    if has("est") || has("cpb") || has("hwp") || has("cppc") {
        bits |= 1 << 7;
    }
    bits
}

impl Processor {
    /// The host's processor as the VM shows it with `cpus` vCPUs, in the
    /// identity's socket; None when the host's CPU is not known.
    pub(super) fn of_host(id: &MachineIdentity, cores: u16, threads: u16) -> Option<Self> {
        let number = |key| host_cpuinfo(key).and_then(|text| text.parse::<u32>().ok());
        let (family, model, stepping) = (
            number("cpu family")?,
            number("model")?,
            number("stepping").unwrap_or(0),
        );
        let vendor = host_cpu_vendor();
        let (maker, edx) = match vendor.as_str() {
            "GenuineIntel" => ("Intel(R) Corporation", 0xbfeb_fbff),
            "AuthenticAMD" => ("Advanced Micro Devices, Inc.", 0x178b_fbff),
            _ => ("", 0x078b_fbff),
        };
        let brand = host_cpuinfo("model name").unwrap_or_default();
        let (max_mhz, current_mhz) = launch::host_cpu_speeds().unwrap_or((0, 0));
        let socket = match (id.cpu_socket.as_str(), vendor.as_str()) {
            ("", "AuthenticAMD") => "AM4",
            ("", _) => "U3E1",
            (socket, _) => socket,
        };
        let flags = host_cpuinfo("flags").unwrap_or_default();
        Some(Self {
            socket: socket.into(),
            manufacturer: maker.into(),
            part: id.cpu_part.clone(),
            family: launch::processor_family(&brand).unwrap_or(0x01),
            brand,
            signature: (signature_eax(family, model, stepping), edx),
            max_mhz,
            current_mhz,
            upgrade: if id.cpu_upgrade == 0 {
                0x01
            } else {
                id.cpu_upgrade
            },
            voltage: id.cpu_voltage,
            cores,
            threads,
            characteristics: characteristics(cores, threads, &flags),
            caches: host_caches(),
        })
    }

    /// The type 7 tables of the processor (L1, L2, L3 as sums over its
    /// cores) and the type 4 table that points at them.
    pub(super) fn tables(&self) -> Vec<Vec<u8>> {
        let mut tables = Vec::new();
        let mut handles = [0xffffu16; 3];
        for level in 1..=3u8 {
            let of_level: Vec<&Cache> = self
                .caches
                .iter()
                .filter(|cache| cache.level == level)
                .collect();
            let Some(first) = of_level.first() else {
                continue;
            };
            // L1 and L2 are per core, L3 is shared by all of them.
            let per_core: u32 = of_level.iter().map(|cache| cache.kib).sum();
            let kib = if level == 3 {
                per_core
            } else {
                per_core * u32::from(self.cores)
            };
            let kind = if of_level.len() > 1 { 5 } else { first.kind };
            let handle = CACHE_HANDLE + u16::from(level) - 1;
            handles[usize::from(level) - 1] = handle;
            tables.push(cache_table(handle, level, kib, kind, first.ways));
        }
        tables.push(self.table(handles));
        tables
    }

    /// The type 4 table, with `caches` the handles of the L1, L2 and L3
    /// tables (0xffff for none).
    fn table(&self, caches: [u16; 3]) -> Vec<u8> {
        let (numbers, strings) = smbios::string_set(&[
            &self.socket,
            &self.manufacturer,
            &self.brand,
            "",
            "",
            &self.part,
        ]);
        let mut table = vec![4, 0x30];
        table.extend(PROCESSOR_HANDLE.to_le_bytes());
        table.extend([numbers[0], 3]); // socket string; central processor
        table.push(if self.family > 0xfe {
            0xfe
        } else {
            self.family as u8
        });
        table.push(numbers[1]);
        table.extend(self.signature.0.to_le_bytes());
        table.extend(self.signature.1.to_le_bytes());
        table.push(numbers[2]);
        table.push(if self.voltage == 0 {
            0
        } else {
            0x80 | self.voltage
        });
        table.extend(100u16.to_le_bytes()); // external clock
        table.extend(self.max_mhz.to_le_bytes());
        table.extend(self.current_mhz.to_le_bytes());
        table.push(0x41); // populated, enabled
        table.push(self.upgrade);
        for handle in caches {
            table.extend(handle.to_le_bytes());
        }
        // Serial and asset tag are string 0 (hidden in public reports too).
        table.extend([numbers[3], numbers[4], numbers[5]]);
        let (cores, threads) = (self.cores.min(255) as u8, self.threads.min(255) as u8);
        table.extend([cores, cores, threads]);
        table.extend(self.characteristics.to_le_bytes());
        table.extend(self.family.to_le_bytes());
        for count in [self.cores, self.cores, self.threads] {
            table.extend(count.to_le_bytes());
        }
        table.extend(strings);
        table
    }
}

/// A type 7 (cache information) structure for one cache level.
fn cache_table(handle: u16, level: u8, kib: u32, kind: u8, ways: u32) -> Vec<u8> {
    let (numbers, strings) = smbios::string_set(&[&format!("L{level} Cache")]);
    // Level in bits 0-2, enabled (bit 7), write back (bit 8).
    let configuration: u16 = u16::from(level - 1) | 0x80 | 0x100;
    // Sizes over 32767 KiB use the 64 KiB granularity.
    let size_word = |kib: u32| -> u16 {
        if kib < 0x8000 {
            kib as u16
        } else {
            0x8000 | (kib / 64).min(0x7fff) as u16
        }
    };
    let mut table = vec![7, 0x1b];
    table.extend(handle.to_le_bytes());
    table.push(numbers[0]);
    table.extend(configuration.to_le_bytes());
    table.extend(size_word(kib).to_le_bytes()); // maximum size
    table.extend(size_word(kib).to_le_bytes()); // installed size
    table.extend(0x0020u16.to_le_bytes()); // supported SRAM: synchronous
    table.extend(0x0020u16.to_le_bytes()); // current SRAM: synchronous
    table.push(0); // speed unknown
    table.push(if level == 1 { 0x05 } else { 0x06 }); // single-bit, multi-bit ECC
    table.push(kind);
    table.push(associativity(ways));
    table.extend(kib.to_le_bytes()); // maximum size 2
    table.extend(kib.to_le_bytes()); // installed size 2
    table.extend(strings);
    table
}
