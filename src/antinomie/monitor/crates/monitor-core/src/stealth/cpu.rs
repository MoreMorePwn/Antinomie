// SPDX-License-Identifier: GPL-3.0-only
//! The host CPU's generation. Passthrough shows it to the guest, so a profile
//! should copy a machine that CPU could really have been sold in.

/// A CPU generation as far as it decides which machines could hold it. Intel's
/// numbers are the marketing generations; the first group covers everything
/// from Skylake to Coffee Lake (and the Comet Lake U parts, which share their
/// CPUID model), the last one everything from Raptor Lake on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CpuGen {
    Core6to9,
    Core10,
    Core11,
    Core12,
    Core13Plus,
    Zen2,
    Zen3,
    Zen4,
    Zen5,
}

impl CpuGen {
    pub fn label(self) -> &'static str {
        match self {
            Self::Core6to9 => "6th to 9th generation Intel Core",
            Self::Core10 => "10th generation Intel Core",
            Self::Core11 => "11th generation Intel Core",
            Self::Core12 => "12th generation Intel Core",
            Self::Core13Plus => "13th generation Intel Core or newer",
            Self::Zen2 => "AMD Ryzen of the Zen 2 generation or older",
            Self::Zen3 => "AMD Ryzen of the Zen 3 generation",
            Self::Zen4 => "AMD Ryzen of the Zen 4 generation",
            Self::Zen5 => "AMD Ryzen of the Zen 5 generation",
        }
    }
}

/// The host CPU as passthrough shows it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HostCpu {
    /// `GenuineIntel`, `AuthenticAMD`, ...
    pub vendor: String,
    /// None when the model is not one the catalog knows (a Xeon Scalable or
    /// EPYC server part, a future CPU): no machine is then ruled out.
    pub generation: Option<CpuGen>,
}

impl HostCpu {
    /// A host known by its vendor only.
    pub fn vendor_only(vendor: &str) -> Self {
        Self {
            vendor: vendor.into(),
            generation: None,
        }
    }

    pub fn detect() -> Self {
        let number = |key| super::host_cpuinfo(key).and_then(|text| text.parse::<u32>().ok());
        let vendor = super::host_cpu_vendor();
        let generation = number("cpu family")
            .zip(number("model"))
            .and_then(|(family, model)| classify(&vendor, family, model));
        Self { vendor, generation }
    }
}

/// The generation of CPUID `family` and `model` (the display values, as
/// /proc/cpuinfo prints them), when the catalog knows it.
pub fn classify(vendor: &str, family: u32, model: u32) -> Option<CpuGen> {
    match (vendor, family) {
        ("GenuineIntel", 6) => match model {
            0x4e | 0x5e | 0x8e | 0x9e => Some(CpuGen::Core6to9),
            0x7d | 0x7e | 0xa5 | 0xa6 => Some(CpuGen::Core10),
            0x8c | 0x8d | 0xa7 | 0xa8 => Some(CpuGen::Core11),
            0x97 | 0x9a | 0xbe => Some(CpuGen::Core12),
            0xb7 | 0xba | 0xbf | 0xaa | 0xac | 0xbd | 0xc5 | 0xc6 | 0xcc => {
                Some(CpuGen::Core13Plus)
            }
            _ => None,
        },
        ("AuthenticAMD", 0x17) => Some(CpuGen::Zen2),
        ("AuthenticAMD", 0x19) => match model {
            0x00..=0x0f | 0x20..=0x5f => Some(CpuGen::Zen3),
            0x10..=0x1f | 0x60..=0xaf => Some(CpuGen::Zen4),
            _ => None,
        },
        ("AuthenticAMD", 0x1a) => Some(CpuGen::Zen5),
        _ => None,
    }
}
