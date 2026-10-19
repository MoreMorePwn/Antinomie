// SPDX-License-Identifier: MIT
//! Register layout as data. One `TargetDescription` per architecture says which
//! registers a debugger sees, in what order, and where each lives inside the
//! regset blobs the guest transfers. The GDB `g` packet image, the target
//! description XML and any UI register view are all derived from it, so a new
//! architecture adds a description and nothing else here.
use super::target::RegsetBlob;
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegKind {
    General,
    CodePointer,
    DataPointer,
    Flags,
    Segment,
    Float,
    FloatControl,
    Vector,
    VectorControl,
    System,
}

/// Where a register's bytes come from.
#[derive(Clone, Copy, Debug)]
pub enum RegSource {
    /// `len` bytes at `offset` of the regset blob tagged `nt_type`; the rest of
    /// the register (up to its bit width) is zero.
    Slice {
        nt_type: u32,
        offset: usize,
        len: usize,
    },
    /// Computed from one or more blobs (for example the x87 tag word, which the
    /// kernel keeps abridged). `write` returns false if it cannot apply.
    Derived {
        read: fn(&RegisterFile) -> Vec<u8>,
        write: fn(&mut RegisterFile, &[u8]) -> bool,
    },
}

#[derive(Clone, Copy, Debug)]
pub struct RegSpec {
    pub name: &'static str,
    pub bits: usize,
    pub feature: &'static str,
    /// GDB register type name, defined in the feature's type block or predefined.
    pub gdb_type: &'static str,
    pub group: Option<&'static str>,
    pub kind: RegKind,
    pub source: RegSource,
}
impl RegSpec {
    pub fn bytes(&self) -> usize {
        self.bits.div_ceil(8)
    }
}

#[derive(Clone, Debug)]
pub struct FeatureSpec {
    pub name: &'static str,
    /// XML type definitions (`<flags>`, `<vector>`, `<union>`) the feature's
    /// registers refer to.
    pub types: &'static str,
}

#[derive(Debug)]
pub struct TargetDescription {
    pub architecture: &'static str,
    pub osabi: Option<&'static str>,
    pub features: Vec<FeatureSpec>,
    pub regs: Vec<RegSpec>,
    /// Register sets a full `g` image needs, in transfer order.
    pub regsets: Vec<u32>,
}

/// The register sets read from one stopped thread, by note type.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RegisterFile {
    sets: BTreeMap<u32, Vec<u8>>,
}
impl RegisterFile {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn insert(&mut self, blob: RegsetBlob) {
        self.sets.insert(blob.nt_type, blob.data);
    }
    pub fn get(&self, nt_type: u32) -> Option<&[u8]> {
        self.sets.get(&nt_type).map(Vec::as_slice)
    }
    pub fn get_mut(&mut self, nt_type: u32) -> Option<&mut Vec<u8>> {
        self.sets.get_mut(&nt_type)
    }
    pub fn blobs(&self) -> impl Iterator<Item = RegsetBlob> + '_ {
        self.sets.iter().map(|(nt_type, data)| RegsetBlob {
            nt_type: *nt_type,
            data: data.clone(),
        })
    }
}

/// One register of a register view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisterValue {
    pub name: &'static str,
    pub bits: usize,
    pub feature: &'static str,
    pub group: Option<&'static str>,
    pub kind: RegKind,
    /// Little endian, exactly `bits / 8` rounded up.
    pub bytes: Vec<u8>,
}

impl TargetDescription {
    /// Length of the full register image a `g` packet carries.
    pub fn image_len(&self) -> usize {
        self.regs.iter().map(RegSpec::bytes).sum()
    }
    pub fn find(&self, name: &str) -> Option<(usize, &RegSpec)> {
        let mut offset = 0;
        for reg in &self.regs {
            if reg.name == name {
                return Some((offset, reg));
            }
            offset += reg.bytes();
        }
        None
    }
    fn read_register(&self, reg: &RegSpec, file: &RegisterFile) -> Vec<u8> {
        let mut bytes = match reg.source {
            RegSource::Slice {
                nt_type,
                offset,
                len,
            } => {
                let mut bytes = vec![0; reg.bytes()];
                if let Some(blob) = file.get(nt_type) {
                    let end = (offset + len.min(bytes.len())).min(blob.len());
                    if end > offset {
                        bytes[..end - offset].copy_from_slice(&blob[offset..end]);
                    }
                }
                bytes
            }
            RegSource::Derived { read, .. } => read(file),
        };
        bytes.resize(reg.bytes(), 0);
        bytes
    }
    /// Registers in debugger order with their current bytes.
    pub fn view(&self, file: &RegisterFile) -> Vec<RegisterValue> {
        self.regs
            .iter()
            .map(|reg| RegisterValue {
                name: reg.name,
                bits: reg.bits,
                feature: reg.feature,
                group: reg.group,
                kind: reg.kind,
                bytes: self.read_register(reg, file),
            })
            .collect()
    }
    /// The `g` packet image: every register's bytes in description order. A
    /// register whose regset is missing reads as zero.
    pub fn serialize(&self, file: &RegisterFile) -> Vec<u8> {
        self.regs
            .iter()
            .flat_map(|reg| self.read_register(reg, file))
            .collect()
    }
    /// Apply a `G` packet image to the blobs it came from. Returns the note
    /// types whose blob changed, which are the only ones to write back.
    pub fn deserialize(&self, image: &[u8], file: &mut RegisterFile) -> Result<Vec<u32>, String> {
        if image.len() != self.image_len() {
            return Err(format!(
                "register image is {} bytes, expected {}",
                image.len(),
                self.image_len()
            ));
        }
        let before = file.clone();
        let mut offset = 0;
        for reg in &self.regs {
            let bytes = &image[offset..offset + reg.bytes()];
            offset += reg.bytes();
            match reg.source {
                RegSource::Slice {
                    nt_type,
                    offset: at,
                    len,
                } => {
                    let Some(blob) = file.get_mut(nt_type) else {
                        continue;
                    };
                    let len = len.min(bytes.len());
                    if at + len <= blob.len() {
                        blob[at..at + len].copy_from_slice(&bytes[..len]);
                    }
                }
                RegSource::Derived { write, .. } => {
                    if !write(file, bytes) {
                        return Err(format!("register {} cannot be written", reg.name));
                    }
                }
            }
        }
        Ok(self
            .regsets
            .iter()
            .copied()
            .filter(|nt| before.get(*nt) != file.get(*nt))
            .collect())
    }
    /// The GDB target description document (`qXfer:features:read` target.xml).
    pub fn xml(&self) -> String {
        let mut xml = String::from(
            "<?xml version=\"1.0\"?>\n<!DOCTYPE target SYSTEM \"gdb-target.dtd\">\n<target version=\"1.0\">\n",
        );
        xml.push_str(&format!(
            "  <architecture>{}</architecture>\n",
            self.architecture
        ));
        if let Some(osabi) = self.osabi {
            xml.push_str(&format!("  <osabi>{osabi}</osabi>\n"));
        }
        for feature in &self.features {
            xml.push_str(&format!("  <feature name=\"{}\">\n", feature.name));
            xml.push_str(feature.types);
            for reg in self.regs.iter().filter(|reg| reg.feature == feature.name) {
                xml.push_str(&format!(
                    "    <reg name=\"{}\" bitsize=\"{}\" type=\"{}\"{}/>\n",
                    reg.name,
                    reg.bits,
                    reg.gdb_type,
                    reg.group
                        .map(|group| format!(" group=\"{group}\""))
                        .unwrap_or_default()
                ));
            }
            xml.push_str("  </feature>\n");
        }
        xml.push_str("</target>\n");
        xml
    }
}
