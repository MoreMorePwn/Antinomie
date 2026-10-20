// SPDX-License-Identifier: MIT
//! MBR and GPT probing of a guest disk.
//!
//! The first sectors of the disk are guest-controlled bytes parsed in the
//! host, so the parser is small and bounded: it reads a fixed window, caps the
//! entry count and entry size, and drops any entry whose range does not fit in
//! the disk. It never allocates from a guest-declared length.
//!
//! A disk whose first sectors hold an ext2/3/4 superblock is a whole-disk
//! filesystem (the Antinomie bases): [`parse`] reports no table for it.
use serde::{Deserialize, Serialize};

/// Bytes of the disk the probe reads: LBA 0 to 127 hold the protective MBR,
/// the GPT header and up to 128 entries of 256 bytes.
pub const HEAD_SECTORS: usize = 128;
pub const SECTOR: u64 = 512;
/// Partitions listed at most.
pub const PARTITION_LIMIT: usize = 128;
/// Partitions whose filesystem is looked at (one `qemu-img dd` each).
pub const FS_PROBE_LIMIT: usize = 16;
/// Largest GPT entry size accepted.
const ENTRY_SIZE_LIMIT: usize = 256;

/// The kind of table.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TableKind {
    #[default]
    Mbr,
    Gpt,
}

impl TableKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Mbr => "MBR",
            Self::Gpt => "GPT",
        }
    }
}

/// What the start of a partition holds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PartitionFs {
    /// Not looked at (past the probe limit) or unreadable.
    #[default]
    Unknown,
    /// An ext2/3/4 superblock.
    Ext4,
    /// Anything else: swap, FAT, an extended-partition container, LVM...
    Other,
}

/// One partition of the disk, by byte range.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Partition {
    /// 1-based, as listed in the table.
    pub index: u32,
    pub start: u64,
    pub length: u64,
    /// "Linux filesystem", "Linux root (x86-64)", "0x83", ...
    pub kind: String,
    /// The GPT partition name; empty for MBR.
    pub name: String,
    pub fs: PartitionFs,
    /// The type says this is a Linux root filesystem.
    pub root: bool,
    /// Whether the type is a Linux data/root type at all.
    pub linux: bool,
}

impl Partition {
    pub fn end(&self) -> u64 {
        self.start.saturating_add(self.length)
    }

    /// `1 · boot · 8.0 MiB · Linux filesystem`.
    pub fn label(&self) -> String {
        let mut text = format!("{}", self.index);
        if !self.name.is_empty() {
            text.push_str(" · ");
            text.push_str(&self.name);
        }
        text.push_str(" · ");
        text.push_str(&super::format_size(self.length));
        text.push_str(" · ");
        text.push_str(&self.kind);
        text
    }

    /// The `--image-opts` string that carves this partition out of the
    /// qcow2 file `top` (`,` doubled in the file name, as QEMU wants).
    pub fn image_opts(&self, top: &std::path::Path) -> String {
        carve_opts(self.start, self.length, top)
    }
}

/// `driver=raw,offset=…,size=…,file.driver=qcow2,file.file.filename=…`.
pub fn carve_opts(start: u64, length: u64, top: &std::path::Path) -> String {
    format!(
        "driver=raw,offset={start},size={length},file.driver=qcow2,file.file.filename={}",
        top.to_string_lossy().replace(',', ",,")
    )
}

/// The partitions of a disk.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PartitionTable {
    pub kind: TableKind,
    pub partitions: Vec<Partition>,
    /// Entries left out because their range does not fit in the disk, or
    /// beyond the limit.
    pub skipped: u32,
}

impl PartitionTable {
    pub fn get(&self, index: u32) -> Option<&Partition> {
        self.partitions
            .iter()
            .find(|partition| partition.index == index)
    }

    /// The partition to open when the user does not choose: the Linux root
    /// that holds ext4, else the largest ext4 one.
    pub fn default_partition(&self) -> Option<u32> {
        let ext4 = || {
            self.partitions
                .iter()
                .filter(|partition| partition.fs == PartitionFs::Ext4)
        };
        ext4()
            .find(|partition| partition.root)
            .or_else(|| {
                ext4().max_by_key(|partition| (partition.length, u32::MAX - partition.index))
            })
            .map(|partition| partition.index)
    }
}

/// Whether the 1 KiB-offset superblock in `sector_two` (the 512 bytes at
/// byte 1024 of a filesystem) is an ext2/3/4 one.
pub fn is_ext4_superblock(sector_two: &[u8]) -> bool {
    sector_two.len() >= 0x3A && u16::from_le_bytes([sector_two[0x38], sector_two[0x39]]) == 0xEF53
}

/// Whether `head` (the disk's first sectors) is a whole-disk ext filesystem.
pub fn is_whole_disk_filesystem(head: &[u8]) -> bool {
    head.get(1024..1536).is_some_and(is_ext4_superblock)
}

fn le32(bytes: &[u8], at: usize) -> u32 {
    bytes.get(at..at + 4).map_or(0, |part| {
        u32::from_le_bytes([part[0], part[1], part[2], part[3]])
    })
}

fn le64(bytes: &[u8], at: usize) -> u64 {
    bytes.get(at..at + 8).map_or(0, |part| {
        u64::from_le_bytes([
            part[0], part[1], part[2], part[3], part[4], part[5], part[6], part[7],
        ])
    })
}

/// `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`, GPT's mixed-endian GUID, upper case.
fn guid(bytes: &[u8]) -> String {
    if bytes.len() < 16 {
        return String::new();
    }
    format!(
        "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        le32(bytes, 0),
        u16::from_le_bytes([bytes[4], bytes[5]]),
        u16::from_le_bytes([bytes[6], bytes[7]]),
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

/// The type name of a GPT partition type GUID, and whether it is a Linux
/// root and a Linux data type.
fn gpt_kind(guid: &str) -> (String, bool, bool) {
    match guid {
        "4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709" => ("Linux root (x86-64)".into(), true, true),
        "B921B045-1DF0-41C3-AF44-4C6F280D3FAE" => ("Linux root (arm64)".into(), true, true),
        "0FC63DAF-8483-4772-8E79-3D69D8477DE4" => ("Linux filesystem".into(), false, true),
        "C12A7328-F81F-11D2-BA4B-00A0C93EC93B" => ("EFI system".into(), false, false),
        "21686148-6449-6E6F-744E-656564454649" => ("BIOS boot".into(), false, false),
        "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F" => ("Linux swap".into(), false, false),
        "E6D6D379-F507-44C2-A23C-238F2A3DF928" => ("Linux LVM".into(), false, false),
        "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7" => ("Basic data".into(), false, false),
        other => (other.to_string(), false, false),
    }
}

fn mbr_kind(code: u8) -> (String, bool, bool) {
    let name = match code {
        0x83 => "Linux",
        0x82 => "Linux swap",
        0x8E => "Linux LVM",
        0x05 | 0x0F | 0x85 => "Extended (logical partitions are not read)",
        0x0B | 0x0C => "FAT32",
        0x07 => "NTFS/exFAT",
        0xEF => "EFI system",
        0xFD => "Linux RAID",
        _ => "",
    };
    let text = if name.is_empty() {
        format!("type 0x{code:02X}")
    } else {
        format!("{name} (0x{code:02X})")
    };
    (text, false, code == 0x83)
}

/// Parse the table in `head`, the first bytes of a disk of `disk_size` bytes.
/// `Ok(None)`: no partition table (a whole-disk filesystem, or blank).
/// `Err`: a table that is damaged or unsupported.
pub fn parse(head: &[u8], disk_size: u64) -> Result<Option<PartitionTable>, String> {
    if is_whole_disk_filesystem(head) {
        return Ok(None);
    }
    if head.len() < 512 || head[510] != 0x55 || head[511] != 0xAA {
        return Ok(None);
    }
    let entries = (0..4).map(|slot| &head[446 + slot * 16..462 + slot * 16]);
    let protective = entries.clone().any(|entry| entry[4] == 0xEE);
    if protective {
        return parse_gpt(head, disk_size).map(Some);
    }
    let mut table = PartitionTable {
        kind: TableKind::Mbr,
        ..PartitionTable::default()
    };
    for (slot, entry) in entries.enumerate() {
        let code = entry[4];
        let start = u64::from(le32(entry, 8)) * SECTOR;
        let length = u64::from(le32(entry, 12)) * SECTOR;
        if code == 0 || length == 0 {
            continue;
        }
        if start.saturating_add(length) > disk_size {
            table.skipped += 1;
            continue;
        }
        let (kind, root, linux) = mbr_kind(code);
        table.partitions.push(Partition {
            index: slot as u32 + 1,
            start,
            length,
            kind,
            name: String::new(),
            fs: if matches!(code, 0x05 | 0x0F | 0x85) {
                PartitionFs::Other
            } else {
                PartitionFs::Unknown
            },
            root,
            linux,
        });
    }
    if table.partitions.is_empty() && table.skipped == 0 {
        // A boot sector signature with no partitions: not a table.
        return Ok(None);
    }
    Ok(Some(table))
}

fn parse_gpt(head: &[u8], disk_size: u64) -> Result<PartitionTable, String> {
    let header = head
        .get(512..1024)
        .filter(|header| header.starts_with(b"EFI PART"))
        .ok_or("the protective MBR announces a GPT, but its header is missing or damaged")?;
    let entries_lba = le64(header, 72);
    let count = le32(header, 80) as usize;
    let size = le32(header, 84) as usize;
    if count == 0
        || count > PARTITION_LIMIT
        || !(128..=ENTRY_SIZE_LIMIT).contains(&size)
        || !size.is_multiple_of(8)
    {
        return Err("the GPT header declares an unsupported entry array".into());
    }
    let start = usize::try_from(entries_lba.saturating_mul(SECTOR))
        .ok()
        .filter(|start| *start >= 1024)
        .ok_or("the GPT entry array is at an unsupported place")?;
    let array = start
        .checked_add(count * size)
        .and_then(|end| head.get(start..end))
        .ok_or("the GPT entry array is outside the part of the disk that is probed")?;
    let first_usable = le64(header, 40);
    let last_usable = le64(header, 48);
    let mut table = PartitionTable {
        kind: TableKind::Gpt,
        ..PartitionTable::default()
    };
    for (slot, entry) in array.chunks_exact(size).enumerate() {
        if entry[..16].iter().all(|byte| *byte == 0) {
            continue;
        }
        let (first, last) = (le64(entry, 32), le64(entry, 40));
        let in_disk = last >= first
            && first >= first_usable
            && last <= last_usable
            && last.saturating_add(1).saturating_mul(SECTOR) <= disk_size;
        if !in_disk {
            table.skipped += 1;
            continue;
        }
        let (kind, root, linux) = gpt_kind(&guid(&entry[..16]));
        let name: String = entry
            .get(56..size.min(128))
            .unwrap_or_default()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes(*pair))
            .take_while(|unit| *unit != 0)
            .map(|unit| char::from_u32(u32::from(unit)).unwrap_or('\u{fffd}'))
            .map(|c| if c.is_control() { '\u{fffd}' } else { c })
            .collect();
        table.partitions.push(Partition {
            index: slot as u32 + 1,
            start: first * SECTOR,
            length: (last - first + 1) * SECTOR,
            kind,
            name,
            fs: PartitionFs::Unknown,
            root,
            linux,
        });
    }
    Ok(table)
}

#[cfg(test)]
mod tests;
